#!/usr/bin/env python3
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

import argparse
import bisect
import contextlib
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


TOOL_NAME = "ntcover-idalib"
DEFAULT_IDALIB_PYTHON = "/home/user/ida-pro-9.3/idalib/python"
IDA_CONFIG_PATH = os.path.expanduser("~/.idapro/ida-config.json")
SUPPORTED_EULA_KEYS = ("EULA 90", "EULA 91", "EULA 92", "EULA 93", "EULA 94")


def http_json(method, url, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as err:
        detail = ""
        try:
            detail = err.read().decode("utf-8", errors="replace").strip()
        except Exception:
            detail = ""
        message = f"HTTP {err.code} {err.reason}"
        if detail:
            message += f": {detail}"
        raise RuntimeError(message) from err
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
    if values is None:
        return []
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


def ensure_idalib_python_path(path):
    if not path:
        return
    if path not in sys.path:
        sys.path.insert(0, path)


def ida_install_dir_from_config():
    if not os.path.exists(IDA_CONFIG_PATH):
        return ""
    try:
        with open(IDA_CONFIG_PATH, encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, ValueError, TypeError):
        return ""
    install_dir = config.get("Paths", {}).get("ida-install-dir", "")
    if not install_dir:
        return ""
    install_dir = os.path.abspath(install_dir)
    return install_dir if os.path.isdir(install_dir) else ""


@contextlib.contextmanager
def temporary_idadir(path):
    previous = os.environ.get("IDADIR")
    try:
        if path:
            os.environ["IDADIR"] = path
        yield
    finally:
        if previous is None:
            os.environ.pop("IDADIR", None)
        else:
            os.environ["IDADIR"] = previous


def check_idalib_environment(idb_path, idalib_python=DEFAULT_IDALIB_PYTHON):
    ensure_idalib_python_path(idalib_python)
    if not os.path.exists(IDA_CONFIG_PATH):
        raise RuntimeError(f"missing IDA config: {IDA_CONFIG_PATH}")
    if idb_path and not os.path.exists(idb_path):
        raise RuntimeError(f"IDB does not exist: {idb_path}")
    install_dir = next(ida_install_dir_candidates(idalib_python), "")
    with temporary_idadir(install_dir):
        try:
            import idapro
        except ImportError as err:
            raise RuntimeError(
                f"failed to import idapro; set PYTHONPATH or --idalib-python to IDA's idalib/python directory"
            ) from err
        accept_ida_eula(install_dir)
    return idapro


def raw_cover_hash(raw):
    offsets = parse_hex_list(raw.get("offsets", []))
    module = raw.get("module", {})
    payload = {
        "module": module.get("name", ""),
        "base": module.get("base", ""),
        "size": module.get("size", ""),
        "raw_cover_complete": raw.get("raw_cover_complete", False),
        "offsets": offsets,
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


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


def open_idb(idb_path, idalib_python=DEFAULT_IDALIB_PYTHON):
    idapro = check_idalib_environment(idb_path, idalib_python)
    result = idapro.open_database(idb_path, True)
    check_open_database_result(result, idb_path)

    import ida_auto

    ida_auto.auto_wait()

    import idautils

    check_database_segments(list(idautils.Segments()), idb_path)
    return idapro


def check_open_database_result(result, idb_path):
    if result != 0:
        raise RuntimeError(f"failed to open IDB: {idb_path} (open_database returned {result})")


def check_database_segments(segments, idb_path):
    if not segments:
        raise RuntimeError(f"opened IDB has no segments: {idb_path}")


def ida_clean_line(line):
    import ida_lines

    return ida_lines.tag_remove(str(line.line))


def analyze_with_ida(idb_path, raw, offsets, lighthouse, decompile, idalib_python=DEFAULT_IDALIB_PYTHON):
    idapro = open_idb(idb_path, idalib_python)
    try:
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
        covered_block_offsets_total = set()
        mapped_raw_offsets = set()

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
            block_ranges = block_ranges_from_ida(blocks, ida_base)
            total_blocks += len(blocks)
            covered_block_offsets, mapped_offsets = partition_offsets_by_blocks(offsets, block_ranges)
            mapped_raw_offsets.update(mapped_offsets)
            covered_block_offsets_total.update(covered_block_offsets)

            if covered_block_offsets:
                covered_functions += 1
            covered_blocks_total += len(covered_block_offsets)

            name = ida_name.get_ea_name(func.start_ea) or f"sub_{func.start_ea:x}"
            functions.append({
                "name": name,
                "file": virtual_pseudocode_file(raw["module"]["name"], name),
                "start_offset": func.start_ea - ida_base,
                "end_offset": func.end_ea - ida_base,
                "covered_blocks": len(covered_block_offsets),
                "total_blocks": len(blocks),
            })

            if hexrays_ready:
                lines = decompile_function(func.start_ea, covered_block_offsets, block_ranges, ida_base)
                if lines:
                    pseudocode.append({
                        "name": name,
                        "file": virtual_pseudocode_file(raw["module"]["name"], name),
                        "lines": lines,
                    })

        snapshot = raw_snapshot(raw, offsets, lighthouse)
        snapshot["module"]["covered_blocks"] = covered_blocks_total
        snapshot["module"]["total_blocks"] = total_blocks
        snapshot["module"]["covered_functions"] = covered_functions
        snapshot["module"]["total_functions"] = len(functions)
        snapshot["functions"] = functions
        snapshot["pseudocode"] = pseudocode
        snapshot["covered_offsets"] = sorted(covered_block_offsets_total)
        snapshot["unmapped"] = sorted(set(snapshot["unmapped"]) | (set(offsets) - mapped_raw_offsets))
        return snapshot
    finally:
        if hasattr(idapro, "close_database"):
            idapro.close_database(False)


def copy_idb_to_scratch(idb_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    suffix = os.path.splitext(idb_path)[1] or ".i64"
    fd, scratch_path = tempfile.mkstemp(prefix="ntcover-idb-", suffix=suffix, dir=output_dir)
    os.close(fd)
    try:
        shutil.copy2(idb_path, scratch_path)
    except Exception:
        try:
            os.remove(scratch_path)
        except OSError:
            pass
        raise
    return scratch_path


def ida_install_dir_candidates(idalib_python):
    candidates = []
    if idalib_python:
        path = os.path.abspath(idalib_python)
        if os.path.basename(path) == "python" and os.path.basename(os.path.dirname(path)) == "idalib":
            candidates.append(os.path.dirname(os.path.dirname(path)))
    config_dir = ida_install_dir_from_config()
    if config_dir:
        candidates.append(config_dir)
    env_dir = os.environ.get("IDADIR")
    if env_dir:
        candidates.append(os.path.abspath(env_dir))
    seen = set()
    for path in candidates:
        if os.path.isdir(path) and path not in seen:
            seen.add(path)
            yield path


def accept_ida_eula(install_dir):
    if not install_dir:
        return
    with temporary_idadir(install_dir):
        import ida_registry

        for key in SUPPORTED_EULA_KEYS:
            ida_registry.reg_write_int(key, 1)


def hexlic_candidates(idalib_python):
    seen = set()
    search_dirs = [os.path.expanduser("~/.idapro")]
    search_dirs.extend(ida_install_dir_candidates(idalib_python))
    for directory in search_dirs:
        if directory in seen or not os.path.isdir(directory):
            continue
        seen.add(directory)
        for name in sorted(os.listdir(directory)):
            if name.lower().endswith(".hexlic"):
                yield os.path.join(directory, name)


def ida_failure_hint(idalib_python):
    if any(True for _ in hexlic_candidates(idalib_python)):
        return ""
    ida_reg = os.path.expanduser("~/.idapro/ida.reg")
    search_dirs = [os.path.expanduser("~/.idapro")]
    search_dirs.extend(ida_install_dir_candidates(idalib_python))
    unique_dirs = []
    for directory in search_dirs:
        if directory not in unique_dirs:
            unique_dirs.append(directory)
    if os.path.exists(ida_reg):
        return (
            f"no .hexlic license file found in {', '.join(unique_dirs)}; "
            f"only legacy ida.reg is present at {ida_reg}"
        )
    return f"no .hexlic license file found in {', '.join(unique_dirs)}"


def analyze_with_ida_subprocess(idb_path, raw, offsets, decompile, idalib_python=DEFAULT_IDALIB_PYTHON):
    with tempfile.TemporaryDirectory(prefix="ntcover-worker-") as work_dir:
        raw_path = os.path.join(work_dir, "raw.json")
        snapshot_path = os.path.join(work_dir, "snapshot.json")
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(raw, f, sort_keys=True)
        cmd = [
            sys.executable,
            os.path.abspath(__file__),
            "--ida-worker",
            "--idb",
            idb_path,
            "--raw-file",
            raw_path,
            "--snapshot-out",
            snapshot_path,
        ]
        if idalib_python:
            cmd.extend(["--idalib-python", idalib_python])
        if not decompile:
            cmd.append("--no-decompile")
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip()
            message = f"IDA worker failed with exit code {proc.returncode}"
            if detail:
                message += f": {detail}"
            hint = ida_failure_hint(idalib_python)
            if hint:
                message += f" ({hint})"
            raise RuntimeError(message)
        with open(snapshot_path, encoding="utf-8") as f:
            return json.load(f)


def block_has_offset(offsets, start, end):
    index = bisect.bisect_left(offsets, start)
    return index < len(offsets) and offsets[index] < end


def block_ranges_from_ida(blocks, ida_base):
    return sorted((block.start_ea - ida_base, block.end_ea - ida_base) for block in blocks)


def block_start_offsets_for_offsets(offsets, block_ranges):
    starts = [start for start, _ in block_ranges]
    covered = set()
    for offset in offsets:
        index = bisect.bisect_right(starts, offset) - 1
        if index >= 0:
            start, end = block_ranges[index]
            if start <= offset < end:
                covered.add(start)
    return covered


def partition_offsets_by_blocks(offsets, block_ranges):
    starts = [start for start, _ in block_ranges]
    covered_blocks = set()
    mapped_offsets = set()
    for offset in offsets:
        index = bisect.bisect_right(starts, offset) - 1
        if index >= 0:
            start, end = block_ranges[index]
            if start <= offset < end:
                covered_blocks.add(start)
                mapped_offsets.add(offset)
    return covered_blocks, mapped_offsets


def virtual_pseudocode_file(module_name, function_name):
    return f"{module_name}/{function_name}.pseudo.c"


def decompile_function(func_ea, covered_block_offsets, block_ranges, ida_base):
    import ida_hexrays

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return []
    if not cfunc:
        return []
    fallback_state = function_coverage_state(len(covered_block_offsets), len(block_ranges))
    lines = []
    for index, line in enumerate(cfunc.get_pseudocode(), start=1):
        line_offsets = pseudocode_line_offsets(cfunc, line, ida_base)
        line_blocks = block_start_offsets_for_offsets(line_offsets, block_ranges)
        state = line_coverage_state(line_blocks, covered_block_offsets)
        if state == "unknown":
            state = fallback_state
        lines.append({
            "line": index,
            "text": ida_clean_line(line),
            "state": state,
            "offsets": sorted(line_blocks),
        })
    return lines


def pseudocode_line_offsets(cfunc, line, ida_base):
    offsets = []
    if hasattr(line, "offsets"):
        offsets.extend(int(value) for value in getattr(line, "offsets"))
    if hasattr(line, "eas"):
        for value in getattr(line, "eas"):
            value = int(value)
            offsets.append(value - ida_base if value >= ida_base else value)
    for attr in ("ea", "address"):
        if hasattr(line, attr):
            value = int(getattr(line, attr))
            if value != 0 and value >= ida_base:
                offsets.append(value - ida_base)
    offsets.extend(pseudocode_line_ctree_offsets(cfunc, line, ida_base))
    return sorted(set(offsets))


def pseudocode_line_ctree_offsets(cfunc, line, ida_base):
    import ida_hexrays
    import ida_idaapi
    import ida_lines

    raw_line = str(line.line)
    clean_line = ida_lines.tag_remove(raw_line)
    offsets = []
    for x in line_item_candidate_columns(clean_line):
        head = ida_hexrays.ctree_item_t()
        item = ida_hexrays.ctree_item_t()
        tail = ida_hexrays.ctree_item_t()
        try:
            ok = cfunc.get_line_item(raw_line, x, True, head, item, tail)
        except Exception:
            continue
        if not ok:
            continue
        for citem in (head, item, tail):
            offsets.extend(ctree_item_offsets(citem, ida_base, ida_idaapi.BADADDR))
    return offsets


def line_item_candidate_columns(clean_line):
    if not clean_line:
        return [0]
    first_text = len(clean_line) - len(clean_line.lstrip())
    columns = {
        0,
        first_text,
        first_text + 1,
        len(clean_line) // 2,
        len(clean_line) - 1,
    }
    return sorted(column for column in columns if 0 <= column < len(clean_line))


def ctree_item_offsets(citem, ida_base, badaddr):
    offsets = []
    for attr in ("it", "e", "i"):
        try:
            ptr = getattr(citem, attr)
        except Exception:
            ptr = None
        if ptr:
            offsets.extend(ea_to_module_offsets([getattr(ptr, "ea", badaddr)], ida_base, badaddr))
    try:
        offsets.extend(ea_to_module_offsets([citem.get_ea()], ida_base, badaddr))
    except Exception:
        pass
    return offsets


def ea_to_module_offsets(eas, ida_base, badaddr):
    offsets = []
    for ea in eas:
        ea = int(ea)
        if ea != badaddr and ea >= ida_base:
            offsets.append(ea - ida_base)
    return offsets


def function_coverage_state(covered_blocks, total_blocks):
    if covered_blocks == 0:
        return "uncovered"
    if covered_blocks == total_blocks:
        return "covered"
    return "partial"


def line_coverage_state(line_blocks, covered_block_offsets):
    if not line_blocks:
        return "unknown"
    covered = len(line_blocks & covered_block_offsets)
    if covered == 0:
        return "uncovered"
    if covered == len(line_blocks):
        return "covered"
    return "partial"


def build_snapshot(args, raw=None):
    if raw is None:
        raw = fetch_raw_cover(args.manager, args.module)
    offsets = parse_hex_list(raw.get("offsets", []))
    lighthouse = []
    if args.idb:
        idb_path = copy_idb_to_scratch(args.idb, args.output_dir)
        try:
            snapshot = analyze_with_ida_subprocess(
                idb_path, raw, offsets, not args.no_decompile, args.idalib_python
            )
        except Exception as err:
            if not args.raw_only_on_ida_error:
                raise
            print(f"IDA analysis unavailable, uploading raw-only snapshot: {err}", file=sys.stderr)
            snapshot = raw_snapshot(raw, offsets, lighthouse)
        finally:
            try:
                os.remove(idb_path)
            except OSError:
                pass
    else:
        snapshot = raw_snapshot(raw, offsets, lighthouse)
    exported_offsets = snapshot.get("covered_offsets") or offsets
    snapshot["lighthouse"] = lighthouse_lines(raw["module"]["name"], exported_offsets)
    path = write_lighthouse(args.output_dir, raw["module"]["name"], exported_offsets)
    print(f"wrote lighthouse coverage: {path} ({len(exported_offsets)} offsets)")
    return snapshot


def run_once(args, raw=None):
    snapshot = build_snapshot(args, raw)
    if not args.no_upload:
        upload_snapshot(args.manager, snapshot)
        print(f"uploaded binary coverage snapshot for {snapshot['module']['name']}")


def run_loop(args):
    last_hash = None
    while True:
        try:
            raw = fetch_raw_cover(args.manager, args.module)
            current_hash = raw_cover_hash(raw)
            if current_hash == last_hash:
                print(f"{TOOL_NAME}: coverage unchanged; skipping IDA analysis")
            else:
                run_once(args, raw)
                last_hash = current_hash
        except (urllib.error.URLError, RuntimeError, OSError, ValueError) as err:
            print(f"{TOOL_NAME}: {err}", file=sys.stderr)
        time.sleep(args.interval)


def parse_args(argv):
    ida_worker = "--ida-worker" in argv
    parser = argparse.ArgumentParser(description="Analyze NTsyzkaller binary coverage with idalib.")
    parser.add_argument("--manager", required=not ida_worker, help="syz-manager URL, for example http://127.0.0.1:56741")
    parser.add_argument("--module", required=not ida_worker, help="target module name, for example afd.sys")
    parser.add_argument("--idb", help="IDA database path. If omitted, only raw module offsets are exported.")
    parser.add_argument("--output-dir", default=".", help="directory for Lighthouse module+offset output")
    parser.add_argument(
        "--idalib-python",
        default=DEFAULT_IDALIB_PYTHON,
        help="IDA idalib/python directory used for importing idapro",
    )
    parser.add_argument("--interval", type=float, default=60.0, help="poll interval in seconds")
    parser.add_argument("--once", action="store_true", help="run one poll/analyze/upload cycle and exit")
    parser.add_argument("--no-upload", action="store_true", help="do not POST the analysis snapshot to syz-manager")
    parser.add_argument("--no-decompile", action="store_true", help="skip Hex-Rays pseudocode extraction")
    parser.add_argument(
        "--raw-only-on-ida-error",
        action="store_true",
        help="fall back to module+offset export if idalib/Hex-Rays analysis fails",
    )
    parser.add_argument("--ida-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--raw-file", help=argparse.SUPPRESS)
    parser.add_argument("--snapshot-out", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def run_ida_worker(args):
    try:
        if not args.raw_file or not args.snapshot_out or not args.idb:
            raise RuntimeError("worker mode requires --raw-file, --snapshot-out, and --idb")
        with open(args.raw_file, encoding="utf-8") as f:
            raw = json.load(f)
        offsets = parse_hex_list(raw.get("offsets", []))
        snapshot = analyze_with_ida(
            args.idb, raw, offsets, [], not args.no_decompile, args.idalib_python
        )
        with open(args.snapshot_out, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, sort_keys=True)
    except Exception as err:
        print(f"{TOOL_NAME} ida-worker: {err}", file=sys.stderr)
        return 1
    return 0


def main(argv):
    args = parse_args(argv)
    if args.ida_worker:
        return run_ida_worker(args)
    if args.once:
        try:
            run_once(args)
        except (urllib.error.URLError, RuntimeError, OSError, ValueError) as err:
            print(f"{TOOL_NAME}: {err}", file=sys.stderr)
            return 1
        return 0
    run_loop(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
