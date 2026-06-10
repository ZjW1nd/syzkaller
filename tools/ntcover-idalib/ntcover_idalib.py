#!/usr/bin/env python3
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

import argparse
import bisect
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


TOOL_NAME = "ntcover-idalib"


def http_json(method, url, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def fetch_raw_cover(manager_url, module_name):
    base = manager_url.rstrip("/")
    query = urllib.parse.urlencode({"module": module_name})
    return http_json("GET", base + "/bincover/raw?" + query)


def upload_snapshot(manager_url, snapshot):
    base = manager_url.rstrip("/")
    return http_json("POST", base + "/bincover/upload", snapshot)


def parse_hex_list(values):
    return sorted({int(value, 16) for value in values})


def lighthouse_lines(module_name, offsets):
    return [f"{module_name}+{offset:x}" for offset in sorted(set(offsets))]


def write_lighthouse(output_dir, module_name, offsets):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{module_name}_coverage_modoff.txt")
    with open(path, "w", encoding="utf-8") as f:
        for line in lighthouse_lines(module_name, offsets):
            f.write(line + "\n")
    return path


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def raw_snapshot(raw, offsets, lighthouse):
    module = raw["module"]
    return {
        "tool": TOOL_NAME,
        "updated_at": utc_now(),
        "module": {
            "name": module["name"],
            "path": module.get("path", ""),
            "base": int(module["base"], 16),
            "size": int(module["size"], 16),
        },
        "covered_offsets": offsets,
        "lighthouse": lighthouse,
        "unmapped": parse_hex_list(raw.get("unmapped", [])),
    }


def open_idb(idb_path):
    try:
        import idapro
    except ImportError as err:
        raise RuntimeError("failed to import idapro; run this tool in an IDA/idalib Python environment") from err

    ok = idapro.open_database(idb_path, True)
    if ok is False:
        raise RuntimeError(f"failed to open IDB: {idb_path}")

    import ida_auto

    ida_auto.auto_wait()


def ida_clean_line(line):
    import ida_lines

    return ida_lines.tag_remove(str(line.line))


def analyze_with_ida(idb_path, raw, offsets, lighthouse, decompile):
    open_idb(idb_path)

    import ida_funcs
    import ida_name
    import idaapi
    import idautils

    ida_base = idaapi.get_imagebase()
    offsets = sorted(set(offsets))

    functions = []
    pseudocode = []
    total_blocks = 0
    covered_blocks_total = 0
    covered_functions = 0

    hexrays_ready = False
    if decompile:
        try:
            import ida_hexrays

            hexrays_ready = ida_hexrays.init_hexrays_plugin()
        except Exception:
            hexrays_ready = False

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        blocks = list(idaapi.FlowChart(func))
        if not blocks:
            continue
        total_blocks += len(blocks)
        covered_blocks = []
        for block in blocks:
            block_start_off = block.start_ea - ida_base
            block_end_off = block.end_ea - ida_base
            if block_has_offset(offsets, block_start_off, block_end_off):
                covered_blocks.append(block)

        if covered_blocks:
            covered_functions += 1
        covered_blocks_total += len(covered_blocks)

        name = ida_name.get_ea_name(func.start_ea) or f"sub_{func.start_ea:x}"
        functions.append({
            "name": name,
            "start_offset": func.start_ea - ida_base,
            "end_offset": func.end_ea - ida_base,
            "covered_blocks": len(covered_blocks),
            "total_blocks": len(blocks),
        })

        if hexrays_ready and covered_blocks:
            lines = decompile_function(func.start_ea, len(covered_blocks), len(blocks))
            if lines:
                pseudocode.append({"name": name, "lines": lines})

    snapshot = raw_snapshot(raw, offsets, lighthouse)
    snapshot["module"]["covered_blocks"] = covered_blocks_total
    snapshot["module"]["total_blocks"] = total_blocks
    snapshot["module"]["covered_functions"] = covered_functions
    snapshot["module"]["total_functions"] = len(functions)
    snapshot["functions"] = functions
    snapshot["pseudocode"] = pseudocode
    return snapshot


def block_has_offset(offsets, start, end):
    index = bisect.bisect_left(offsets, start)
    return index < len(offsets) and offsets[index] < end


def decompile_function(func_ea, covered_blocks, total_blocks):
    import ida_hexrays

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return []
    if not cfunc:
        return []
    if covered_blocks == 0:
        state = "uncovered"
    elif covered_blocks == total_blocks:
        state = "covered"
    else:
        state = "partial"
    lines = []
    for index, line in enumerate(cfunc.get_pseudocode(), start=1):
        lines.append({
            "line": index,
            "text": ida_clean_line(line),
            "state": state,
        })
    return lines


def build_snapshot(args):
    raw = fetch_raw_cover(args.manager, args.module)
    offsets = parse_hex_list(raw.get("offsets", []))
    lighthouse = lighthouse_lines(raw["module"]["name"], offsets)
    path = write_lighthouse(args.output_dir, raw["module"]["name"], offsets)
    print(f"wrote lighthouse coverage: {path} ({len(offsets)} offsets)")
    if args.idb:
        try:
            return analyze_with_ida(args.idb, raw, offsets, lighthouse, not args.no_decompile)
        except Exception as err:
            if not args.raw_only_on_ida_error:
                raise
            print(f"IDA analysis failed, uploading raw-only snapshot: {err}", file=sys.stderr)
    return raw_snapshot(raw, offsets, lighthouse)


def run_once(args):
    snapshot = build_snapshot(args)
    if not args.no_upload:
        upload_snapshot(args.manager, snapshot)
        print(f"uploaded binary coverage snapshot for {snapshot['module']['name']}")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Analyze NTsyzkaller binary coverage with idalib.")
    parser.add_argument("--manager", required=True, help="syz-manager URL, for example http://127.0.0.1:56741")
    parser.add_argument("--module", required=True, help="target module name, for example afd.sys")
    parser.add_argument("--idb", help="IDA database path. If omitted, only raw module offsets are exported.")
    parser.add_argument("--output-dir", default=".", help="directory for Lighthouse module+offset output")
    parser.add_argument("--interval", type=float, default=60.0, help="poll interval in seconds")
    parser.add_argument("--once", action="store_true", help="run one poll/analyze/upload cycle and exit")
    parser.add_argument("--no-upload", action="store_true", help="do not POST the analysis snapshot to syz-manager")
    parser.add_argument("--no-decompile", action="store_true", help="skip Hex-Rays pseudocode extraction")
    parser.add_argument(
        "--raw-only-on-ida-error",
        action="store_true",
        help="fall back to module+offset export if idalib/Hex-Rays analysis fails",
    )
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    while True:
        try:
            run_once(args)
        except (urllib.error.URLError, RuntimeError, OSError, ValueError) as err:
            print(f"{TOOL_NAME}: {err}", file=sys.stderr)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
