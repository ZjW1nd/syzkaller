#!/usr/bin/env python3
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

import importlib.util
import os
import tempfile
import types
import unittest


SCRIPT = os.path.join(os.path.dirname(__file__), "ntcover_idalib.py")
SPEC = importlib.util.spec_from_file_location("ntcover_idalib", SCRIPT)
ntcover = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ntcover)


class NtCoverIdalibTest(unittest.TestCase):
    def test_block_start_offsets_use_half_open_intervals(self):
        blocks = [(0x100, 0x110), (0x110, 0x130)]
        offsets = [0x100, 0x10F, 0x110, 0x12F, 0x130]

        got = ntcover.block_start_offsets_for_offsets(offsets, blocks)

        self.assertEqual(got, {0x100, 0x110})

    def test_partition_offsets_deduplicates_blocks(self):
        blocks = [(0x100, 0x120), (0x200, 0x220)]
        offsets = [0x101, 0x108, 0x205, 0x300]

        covered, mapped = ntcover.partition_offsets_by_blocks(offsets, blocks)

        self.assertEqual(covered, {0x100, 0x200})
        self.assertEqual(mapped, {0x101, 0x108, 0x205})

    def test_line_coverage_state(self):
        covered = {0x100, 0x200}

        self.assertEqual(ntcover.line_coverage_state(set(), covered), "unknown")
        self.assertEqual(ntcover.line_coverage_state({0x300}, covered), "uncovered")
        self.assertEqual(ntcover.line_coverage_state({0x100}, covered), "covered")
        self.assertEqual(ntcover.line_coverage_state({0x100, 0x300}, covered), "partial")

    def test_lighthouse_lines_are_module_plus_hex_offset(self):
        got = ntcover.lighthouse_lines("afd.sys", [0x20, 0x10, 0x20])

        self.assertEqual(got, ["afd.sys+10", "afd.sys+20"])

    def test_line_item_candidate_columns_cover_statement_positions(self):
        got = ntcover.line_item_candidate_columns("  call(arg);")

        self.assertEqual(got, [0, 2, 3, 6, 11])

    def test_ea_to_module_offsets_filters_badaddr_and_external_values(self):
        got = ntcover.ea_to_module_offsets([0x140001000, 0x100, 0xFFFFFFFFFFFFFFFF], 0x140000000, 0xFFFFFFFFFFFFFFFF)

        self.assertEqual(got, [0x1000])

    def test_raw_cover_hash_is_stable_for_offset_order(self):
        raw_a = {
            "module": {"name": "afd.sys", "base": "0x1000", "size": "0x2000"},
            "offsets": ["0x20", "0x10", "0x10"],
            "raw_cover_complete": True,
        }
        raw_b = {
            "module": {"name": "afd.sys", "base": "0x1000", "size": "0x2000"},
            "offsets": ["0x10", "0x20"],
            "raw_cover_complete": True,
        }

        self.assertEqual(ntcover.raw_cover_hash(raw_a), ntcover.raw_cover_hash(raw_b))

    def test_raw_cover_hash_treats_null_offsets_as_empty(self):
        raw_a = {
            "module": {"name": "afd.sys", "base": "0x1000", "size": "0x2000"},
            "offsets": None,
            "raw_cover_complete": False,
        }
        raw_b = {
            "module": {"name": "afd.sys", "base": "0x1000", "size": "0x2000"},
            "offsets": [],
            "raw_cover_complete": False,
        }

        self.assertEqual(ntcover.raw_cover_hash(raw_a), ntcover.raw_cover_hash(raw_b))

    def test_open_database_result_requires_zero(self):
        ntcover.check_open_database_result(0, "afd.sys.i64")

        with self.assertRaisesRegex(RuntimeError, "open_database returned 4"):
            ntcover.check_open_database_result(4, "afd.sys.i64")

    def test_database_segments_must_not_be_empty(self):
        ntcover.check_database_segments([0x140001000], "afd.sys.i64")

        with self.assertRaisesRegex(RuntimeError, "no segments"):
            ntcover.check_database_segments([], "afd.sys.i64")

    def test_raw_snapshot_writes_lighthouse_export(self):
        raw = {
            "module": {"name": "afd.sys", "base": "0x1000", "size": "0x2000"},
            "offsets": ["0x20", "0x10"],
        }
        with tempfile.TemporaryDirectory() as output_dir:
            args = types.SimpleNamespace(
                manager="",
                module="afd.sys",
                idb=None,
                output_dir=output_dir,
                no_decompile=False,
                raw_only_on_ida_error=False,
                idalib_python="",
            )

            snapshot = ntcover.build_snapshot(args, raw)

            self.assertEqual(snapshot["covered_offsets"], [0x10, 0x20])
            self.assertEqual(snapshot["lighthouse"], ["afd.sys+10", "afd.sys+20"])
            path = os.path.join(output_dir, "afd.sys_coverage_modoff.txt")
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), "afd.sys+10\nafd.sys+20\n")

    def test_ida_analysis_uses_temporary_idb_copy(self):
        raw = {
            "module": {"name": "afd.sys", "base": "0x1000", "size": "0x2000"},
            "offsets": ["0x10"],
        }
        with tempfile.TemporaryDirectory() as output_dir:
            idb_path = os.path.join(output_dir, "source.i64")
            with open(idb_path, "wb") as f:
                f.write(b"idb")
            args = types.SimpleNamespace(
                manager="",
                module="afd.sys",
                idb=idb_path,
                output_dir=output_dir,
                no_decompile=True,
                raw_only_on_ida_error=False,
                idalib_python="",
            )
            seen = {}
            original = ntcover.analyze_with_ida

            def fake_analyze(path, got_raw, offsets, lighthouse, decompile, idalib_python):
                seen["path"] = path
                self.assertNotEqual(path, idb_path)
                self.assertTrue(path.startswith(output_dir + os.sep))
                self.assertTrue(os.path.exists(path))
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), b"idb")
                return ntcover.raw_snapshot(got_raw, offsets, lighthouse)

            ntcover.analyze_with_ida = fake_analyze
            try:
                snapshot = ntcover.build_snapshot(args, raw)
            finally:
                ntcover.analyze_with_ida = original

            self.assertEqual(snapshot["covered_offsets"], [0x10])
            self.assertIn("path", seen)
            self.assertFalse(os.path.exists(seen["path"]))


if __name__ == "__main__":
    unittest.main()
