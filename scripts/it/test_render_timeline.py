#!/usr/bin/env python3
"""Tests for render-timeline.py. Run: python3 scripts/it/test_render_timeline.py"""

import contextlib
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "render_timeline", Path(__file__).resolve().parent / "render-timeline.py"
)
rt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rt)


def block(policy, name, slot, start, took, passed=True):
    return {"slot": slot, "policy": policy, "block": name, "startMs": start, "durationMs": took, "passed": passed}


def report(**overrides):
    base = {
        "schemaVersion": 1,
        "gatewayVersion": "1.2.0",
        "blockParallel": 2,
        "buildSeconds": 190.4,
        "wallMs": 145_000,
        "blocks": [
            block("cors", "cors/sqlite", 1, 0, 90_000),
            block("cors", "cors/postgres", 2, 0, 100_000),
            block("basic-auth", "basic-auth/sqlite", 1, 90_000, 30_000),
            block("basic-auth", "basic-auth/postgres", 2, 100_000, 40_000, passed=False),
        ],
        "compiles": [{"policy": "cors", "durationMs": 20_000, "passed": True}],
        "skipped": ["jwt-auth"],
    }
    base.update(overrides)
    return base


def mermaid_blocks(text):
    return re.findall(r"```mermaid\n(.*?)```", text, re.S)


class FormatTests(unittest.TestCase):
    def test_duration_leaves_out_the_leading_zero_units(self):
        self.assertEqual("0s", rt.duration(0))
        self.assertEqual("59s", rt.duration(59_999))
        self.assertEqual("1m 5s", rt.duration(65_000))
        self.assertEqual("1h 1m 1s", rt.duration(3_661_000))
        self.assertEqual("0s", rt.duration(-5000))

    def test_clock_counts_from_the_start_of_the_run(self):
        self.assertEqual("0:00", rt.clock(0))
        self.assertEqual("2:05", rt.clock(125_000))
        self.assertEqual("1:01:01", rt.clock(3_661_000))

    def test_a_block_name_that_begins_with_its_policy_stands_alone(self):
        self.assertEqual("cors/sqlite", rt.block_name(block("cors", "cors/sqlite", 1, 0, 1)))
        self.assertEqual("cors", rt.block_name(block("cors", "cors", 1, 0, 1)))
        self.assertEqual("a-b-disabled/sqlite", rt.block_name(block("a-b", "a-b-disabled/sqlite", 1, 0, 1)))

    def test_a_block_name_without_its_policy_gets_the_policy_in_front(self):
        self.assertEqual("policy: other/sqlite", rt.block_name(block("policy", "other/sqlite", 1, 0, 1)))

    def test_labels_are_escaped_so_a_name_cannot_inject_diagram_syntax(self):
        text = rt.label('a"b<c>`d')
        self.assertNotIn('"', text)
        self.assertNotIn("<c>", text)
        self.assertNotIn("`", text)


class LaneTests(unittest.TestCase):
    def test_every_lane_lists_the_blocks_it_ran_in_order(self):
        lanes = dict(rt.lanes(report()))
        self.assertEqual(["cors/sqlite", "basic-auth/sqlite"], [b["block"] for b in lanes[1]])
        self.assertEqual(["cors/postgres", "basic-auth/postgres"], [b["block"] for b in lanes[2]])

    def test_lanes_are_numbered_from_the_recorded_slot(self):
        blocks = [block("a", "a/x", 3, 0, 10), block("b", "b/x", 1, 0, 10)]
        self.assertEqual([1, 3], [number for number, _ in rt.lanes(report(blocks=blocks))])

    def test_blocks_without_a_recorded_lane_go_to_the_first_free_one(self):
        blocks = [
            {"policy": "a", "block": "a/1", "startMs": 0, "durationMs": 100, "passed": True},
            {"policy": "b", "block": "b/1", "startMs": 10, "durationMs": 50, "passed": True},
            {"policy": "c", "block": "c/1", "startMs": 60, "durationMs": 10, "passed": True},
            {"policy": "d", "block": "d/1", "startMs": 120, "durationMs": 10, "passed": True},
        ]
        lanes = [[b["block"] for b in lane] for _, lane in rt.lanes(report(blocks=blocks))]
        self.assertEqual([["a/1", "d/1"], ["b/1", "c/1"]], lanes)

    def test_a_lane_reports_how_long_it_was_busy_and_when_it_finished(self):
        lanes = dict(rt.lanes(report()))
        self.assertEqual((120_000, 120_000), rt.lane_totals(lanes[1]))
        self.assertEqual((140_000, 140_000), rt.lane_totals(lanes[2]))

    def test_a_lane_that_waited_between_blocks_was_busy_for_less_than_it_ran(self):
        lane = [block("a", "a/1", 1, 0, 10_000), block("a", "a/2", 1, 30_000, 10_000)]
        self.assertEqual((20_000, 40_000), rt.lane_totals(lane))


class DiagramTests(unittest.TestCase):
    def setUp(self):
        self.graph = mermaid_blocks(rt.render(report()))[0]

    def test_draws_a_lane_for_every_slot(self):
        self.assertTrue(self.graph.startswith("flowchart LR\n"))
        self.assertIn('subgraph lane1["Lane 1"]', self.graph)
        self.assertIn('subgraph lane2["Lane 2"]', self.graph)

    def test_every_block_shows_its_name_time_and_start_and_end(self):
        self.assertIn("✅ cors/sqlite<br/>1m 30s<br/>0:00 → 1:30", self.graph)
        self.assertIn("❌ basic-auth/postgres<br/>40s<br/>1:40 → 2:20", self.graph)

    def test_a_failed_block_is_drawn_red(self):
        self.assertRegex(self.graph, r'r2b1\("❌ basic-auth/postgres.*"\):::fail')
        self.assertRegex(self.graph, r'r1b0\("✅ cors/sqlite.*"\):::pass')

    def test_each_lane_ends_with_its_completion_time(self):
        self.assertIn("Lane 1 done<br/>finished at 2m 0s · busy 2m 0s<br/>2 blocks", self.graph)
        self.assertIn("Lane 2 done<br/>finished at 2m 20s · busy 2m 20s<br/>2 blocks", self.graph)

    def test_the_run_start_and_end_cards_carry_the_whole_run(self):
        self.assertIn("Run start<br/>gateway 1.2.0<br/>gateway built in 3m 10s<br/>2 lanes", self.graph)
        self.assertIn("All blocks done<br/>4 blocks · 3 passed · 1 failed<br/>total 2m 25s", self.graph)

    def test_arrows_chain_the_start_the_blocks_of_a_lane_and_the_end(self):
        for edge in ("start --> r1b0", "r1b0 --> r1b1", "r1b1 --> r1end", "r1end --> done",
                     "start --> r2b0", "r2b0 --> r2b1", "r2b1 --> r2end", "r2end --> done"):
            self.assertIn(edge, self.graph)

    def test_draws_no_bar_chart(self):
        self.assertNotIn("xychart", rt.render(report()))

    def test_a_run_with_many_lanes_is_split_into_diagrams_the_summary_can_render(self):
        blocks = [block(f"policy-{lane:02d}", f"policy-{lane:02d}/block-{i:02d}", lane, i * 1000, 900)
                  for lane in range(1, 41) for i in range(30)]
        text = rt.render(report(blocks=blocks, blockParallel=40, wallMs=30_000))
        graphs = mermaid_blocks(text)
        self.assertGreater(len(graphs), 1)
        for graph in graphs:
            self.assertLessEqual(len(graph), rt.MAX_DIAGRAM_CHARS)
            self.assertLessEqual(graph.count(" --> "), rt.MAX_DIAGRAM_EDGES)
            self.assertIn("Run start", graph)
            self.assertIn("All blocks done", graph)
        drawn = sorted(int(n) for graph in graphs for n in re.findall(r"subgraph lane(\d+)\[", graph))
        self.assertEqual(list(range(1, 41)), drawn)


SAMPLES = [
    {"atMs": 0, "cpuPercent": 10, "memUsedMb": 4096, "memTotalMb": 16384},
    {"atMs": 50_000, "cpuPercent": 80, "memUsedMb": 9216, "memTotalMb": 16384},
    {"atMs": 100_000, "cpuPercent": 60, "memUsedMb": 8192, "memTotalMb": 16384},
    {"atMs": 140_000, "cpuPercent": 30, "memUsedMb": 5120, "memTotalMb": 16384},
]


class LoadTests(unittest.TestCase):
    def test_a_window_holds_the_average_and_peak_of_the_samples_inside_it(self):
        stats = rt.load(SAMPLES, 0, 90_000)
        self.assertEqual(45, stats["cpuAvg"])
        self.assertEqual(80, stats["cpuPeak"])
        self.assertEqual(6656, stats["memAvg"])
        self.assertEqual(9216, stats["memPeak"])
        self.assertEqual(16384, stats["memTotal"])

    def test_a_window_without_a_sample_uses_the_sample_nearest_its_middle(self):
        stats = rt.load(SAMPLES, 60_000, 62_000)
        self.assertEqual(80, stats["cpuAvg"])

    def test_there_is_no_load_without_samples(self):
        self.assertIsNone(rt.load([], 0, 10))
        self.assertEqual("", rt.load_line(None))

    def test_gigabytes_have_one_decimal(self):
        self.assertEqual("9.0 GB", rt.gigabytes(9216))
        self.assertEqual("0.5 GB", rt.gigabytes(512))


class DiagramLoadTests(unittest.TestCase):
    def setUp(self):
        self.report = report(samples=SAMPLES, cores=4)
        self.text = rt.render(self.report)
        self.graph = mermaid_blocks(self.text)[0]

    def test_every_block_shows_the_machines_cpu_and_ram_while_it_ran(self):
        self.assertIn("cors/sqlite<br/>1m 30s<br/>0:00 → 1:30<br/>CPU 45% · RAM 9.0 GB", self.graph)
        self.assertIn("basic-auth/postgres<br/>40s<br/>1:40 → 2:20<br/>CPU 45% · RAM 8.0 GB", self.graph)

    def test_every_lane_shows_its_cpu_and_ram_over_its_whole_run(self):
        self.assertIn("Lane 1 done<br/>finished at 2m 0s · busy 2m 0s<br/>2 blocks<br/>CPU 50% · RAM 9.0 GB", self.graph)

    def test_the_start_card_names_the_machine(self):
        self.assertIn("machine: 4 cores · 16.0 GB RAM", self.graph)

    def test_the_end_card_carries_the_load_of_the_whole_run(self):
        self.assertIn("CPU avg 45% · peak 80%<br/>RAM avg 6.5 GB · peak 9.0 GB", self.graph)

    def test_a_table_gives_the_load_of_the_whole_run(self):
        self.assertIn("| 4 | 16.0 GB | 45% | 80% | 6.5 GB | 9.0 GB |", self.text)

    def test_a_timeline_without_samples_shows_no_cpu_or_ram(self):
        text = rt.render(report())
        self.assertNotIn("CPU", mermaid_blocks(text)[0])
        self.assertNotIn("Machine during the run", text)

    def test_a_timeline_from_before_samples_existed_still_renders(self):
        old = report()
        old.pop("samples", None)
        old.pop("cores", None)
        self.assertIn("flowchart LR", rt.render(old))


class SuiteTests(unittest.TestCase):
    def test_a_suite_runs_from_its_first_block_start_to_its_last_block_end(self):
        rows = {r["policy"]: r for r in rt.suites(report())}
        self.assertEqual(100_000, rows["cors"]["wallMs"])
        self.assertEqual(50_000, rows["basic-auth"]["wallMs"])
        self.assertEqual(190_000, rows["cors"]["blockMs"])
        self.assertEqual(1, rows["basic-auth"]["failed"])
        self.assertEqual("cors/postgres", rows["cors"]["slowest"]["block"])
        self.assertEqual(20_000, rows["cors"]["compileMs"])
        self.assertIsNone(rows["basic-auth"]["compileMs"])

    def test_the_slowest_suite_comes_first_and_equal_ones_by_name(self):
        self.assertEqual(["cors", "basic-auth"], [r["policy"] for r in rt.suites(report())])
        blocks = [block("b", "b/x", 1, 0, 10_000), block("a", "a/x", 2, 0, 10_000)]
        self.assertEqual(["a", "b"], [r["policy"] for r in rt.suites(report(blocks=blocks))])


class RenderTests(unittest.TestCase):
    def test_summarises_the_run(self):
        text = rt.render(report())
        self.assertIn("### Integration suites on gateway 1.2.0: execution map", text)
        self.assertIn("| Gateway build | 3m 10s |", text)
        self.assertIn("| Blocks | 4 (3 passed, 1 failed) |", text)
        self.assertIn("1 with nothing to run on this version", text)
        self.assertIn("| Lanes (blocks at the same time, at most) | 2 (2 used) |", text)
        self.assertIn("| Time running the suites | 2m 25s |", text)
        self.assertIn("| Time of all blocks added up | 4m 20s |", text)

    def test_lists_the_time_of_every_lane(self):
        text = rt.render(report())
        self.assertIn("| 1 | 2 | 2m 0s | 2m 0s | 100% |", text)
        self.assertIn("| 2 | 2 | 2m 20s | 2m 20s | 100% |", text)

    def test_keeps_the_time_of_every_suite_in_a_collapsed_table(self):
        text = rt.render(report())
        self.assertIn("<summary>Time per suite</summary>", text)
        self.assertIn("| cors | ✅ | 2 | 1m 40s | 3m 10s | cors/postgres (1m 40s) | 20s |", text)
        self.assertIn("| basic-auth | ❌ 1 failed | 2 | 50s | 1m 10s | basic-auth/postgres (40s) |  |", text)

    def test_a_run_without_blocks_says_so_and_draws_nothing(self):
        text = rt.render(report(blocks=[], compiles=[]))
        self.assertIn("No block ran.", text)
        self.assertNotIn("mermaid", text)

    def test_a_missing_build_time_is_reported_as_not_recorded(self):
        text = rt.render(report(buildSeconds=0))
        self.assertIn("| Gateway build | not recorded |", text)
        self.assertNotIn("gateway built in", text)

    def test_rejects_an_unknown_schema(self):
        with self.assertRaises(ValueError):
            rt.render(report(schemaVersion=2))


class MainTests(unittest.TestCase):
    def run_main(self, path):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rt.main(["--input", str(path)])
        return code, out.getvalue()

    def test_prints_the_summary_of_a_timeline_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "timeline.json"
            path.write_text(json.dumps(report()), encoding="utf-8")
            code, text = self.run_main(path)
        self.assertEqual(0, code)
        self.assertIn("### Integration suites on gateway 1.2.0", text)

    def test_a_missing_file_prints_a_note_and_still_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, text = self.run_main(Path(tmp) / "missing.json")
        self.assertEqual(0, code)
        self.assertIn("No timing is available", text)

    def test_a_malformed_file_prints_a_note_and_still_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "timeline.json"
            path.write_text("{not json", encoding="utf-8")
            code, text = self.run_main(path)
        self.assertEqual(0, code)
        self.assertIn("No timing is available", text)


if __name__ == "__main__":
    unittest.main()
