#!/usr/bin/env python3
"""Print the execution map of one gateway version's integration run, as GitHub job summary markdown.

Input is the timeline JSON `run-suites -timeline` writes (schemaVersion 1). A run keeps `blockParallel`
runners busy: each runner runs one block at a time and takes the next waiting block when it ends the
last. The map draws one lane per runner with the blocks it ran, in order, each with its policy, its
time and its start and end, then the runner's own completion time and the completion time of the whole
run. A missing or unreadable timeline prints a note and exits zero, so a reporting problem never
fails the job.

Usage: python3 scripts/it/render-timeline.py --input it-timeline-1.2.0.json >> "$GITHUB_STEP_SUMMARY"
"""

import argparse
import html
import json
import re
import sys
from pathlib import Path

SCHEMA_VERSION = 1
MAX_DIAGRAM_CHARS = 40_000
MAX_DIAGRAM_EDGES = 350
LABEL_WIDTH = 28
STYLE = """  classDef pass fill:#ffffff,stroke:#1a7f37,stroke-width:1px,color:#1f2328,rx:8,ry:8;
  classDef fail fill:#ffebe9,stroke:#cf222e,stroke-width:1px,color:#82071e,rx:8,ry:8;
  classDef neutral fill:#ffffff,stroke:#d1d9e0,stroke-width:1px,color:#1f2328,rx:8,ry:8;
  linkStyle default stroke:#8c959f,stroke-width:1px;
"""


def duration(milliseconds):
    """Return milliseconds as "1h 2m 3s", leaving out the leading units that are zero."""
    seconds = max(0, int(milliseconds) // 1000)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def clock(milliseconds):
    """Return an offset from the start of the run as "m:ss", or "h:mm:ss" from the first hour on."""
    seconds = max(0, int(milliseconds) // 1000)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes}:{seconds:02d}"


def label(value, width=LABEL_WIDTH):
    """Escape a name for a diagram label and wrap a long one, without inserting diagram syntax."""
    parts = re.findall(r".{1,%d}(?:[- /]|$)|.{1,%d}" % (width, width), str(value))
    return "<br/>".join(html.escape(p.strip(), quote=True).replace("`", "&#96;") for p in parts if p.strip())


def block_name(block):
    """Return the block's name, with its policy in front when the name does not begin with it."""
    name, policy = block["block"], block["policy"]
    if name == policy or name.startswith((policy + "/", policy + "-")):
        return name
    return f"{policy}: {name}"


def end_of(block):
    return block["startMs"] + block["durationMs"]


def runners(report):
    """Return the runners as (number, blocks) pairs, with each runner's blocks in the order it ran them.

    The timeline records the runner of every block. For a timeline that does not, blocks are placed on
    the first runner that is free when they start.
    """
    blocks = sorted(report["blocks"], key=lambda b: (b["startMs"], b["block"]))
    if blocks and all(b.get("slot", 0) >= 1 for b in blocks):
        lanes = {}
        for block in blocks:
            lanes.setdefault(block["slot"], []).append(block)
        return sorted(lanes.items())
    lanes = []
    for block in blocks:
        for lane in lanes:
            if end_of(lane[-1]) <= block["startMs"]:
                lane.append(block)
                break
        else:
            lanes.append([block])
    return [(number, lane) for number, lane in enumerate(lanes, start=1)]


def lane_totals(blocks):
    """Return how long a runner was busy and when it finished its last block."""
    return sum(b["durationMs"] for b in blocks), max(end_of(b) for b in blocks)


def card(node, text, status):
    return f'  {node}("{text}"):::{status}\n'


def lane_body(number, blocks):
    """Return the diagram lines of one runner's lane, and the id of its last node."""
    busy, finished = lane_totals(blocks)
    failed = sum(1 for b in blocks if not b["passed"])
    body = f'  subgraph lane{number}["Runner {number}"]\n    direction LR\n'
    ids = []
    for index, block in enumerate(blocks):
        node = f"r{number}b{index}"
        ids.append(node)
        icon = "✅" if block["passed"] else "❌"
        text = (f'{icon} {label(block_name(block))}<br/>{duration(block["durationMs"])}'
                f'<br/>{clock(block["startMs"])} → {clock(end_of(block))}')
        body += card(node, text, "pass" if block["passed"] else "fail")
    end = f"r{number}end"
    text = (f"Runner {number} done<br/>finished at {duration(finished)} · busy {duration(busy)}"
            f"<br/>{len(blocks)} blocks")
    body += card(end, text, "fail" if failed else "neutral")
    body += "  end\n"
    body += f"  style lane{number} fill:#f6f8fa,stroke:#d1d9e0,color:#1f2328,rx:8,ry:8\n"
    return body, ids + [end]


def diagram(lanes, report):
    """Return one fenced diagram that holds the given runners."""
    version = report["gatewayVersion"]
    blocks = report["blocks"]
    failed = sum(1 for b in blocks if not b["passed"])
    start = f"Run start<br/>gateway {label(version)}"
    if report.get("buildSeconds"):
        start += f"<br/>gateway built in {duration(report['buildSeconds'] * 1000)}"
    start += f"<br/>{report['blockParallel']} runners"
    body = card("start", start, "neutral")
    done = (f"All blocks done<br/>{len(blocks)} blocks · {len(blocks) - failed} passed · {failed} failed"
            f"<br/>total {duration(report['wallMs'])}")
    body += card("done", done, "fail" if failed else "neutral")
    for number, lane in lanes:
        lane_text, ids = lane_body(number, lane)
        body += lane_text
        nodes = ["start"] + ids + ["done"]
        body += "".join(f"  {a} --> {b}\n" for a, b in zip(nodes, nodes[1:]))
    graph = "flowchart LR\n" + body + STYLE
    return graph


def fenced(graph):
    return "```mermaid\n" + graph + "```\n\n"


def diagrams(report):
    """Yield the map as one fenced diagram, or as several when the runners do not fit in one.

    A diagram is bounded by the size and the edge count the summary can render, so the runners are
    split over as many diagrams as needed, each with the run's start and end.
    """
    group = []
    for lane in runners(report):
        candidate = group + [lane]
        graph = diagram(candidate, report)
        if group and (len(graph) > MAX_DIAGRAM_CHARS or graph.count(" --> ") > MAX_DIAGRAM_EDGES):
            yield fenced(diagram(group, report))
            group = [lane]
        else:
            group = candidate
    if group:
        yield fenced(diagram(group, report))


def suites(report):
    """Group the blocks by policy and return the suites, the slowest first.

    A suite's wall time runs from the start of its first block to the end of its last one, so it
    includes the time its blocks waited for a free runner.
    """
    compiles = {c["policy"]: c["durationMs"] for c in report["compiles"]}
    grouped = {}
    for block in report["blocks"]:
        grouped.setdefault(block["policy"], []).append(block)
    rows = []
    for policy, blocks in grouped.items():
        slowest = max(blocks, key=lambda b: b["durationMs"])
        rows.append({
            "policy": policy,
            "blocks": len(blocks),
            "failed": sum(1 for b in blocks if not b["passed"]),
            "wallMs": max(end_of(b) for b in blocks) - min(b["startMs"] for b in blocks),
            "blockMs": sum(b["durationMs"] for b in blocks),
            "slowest": slowest,
            "compileMs": compiles.get(policy),
        })
    return sorted(rows, key=lambda r: (-r["wallMs"], r["policy"]))


def render(report):
    """Return the whole summary for one timeline."""
    if report.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("unsupported timeline schema")
    version = report["gatewayVersion"]
    blocks = report["blocks"]
    out = [f"### Integration suites on gateway {version}: execution map\n\n"]
    if not blocks:
        out.append("No block ran.\n")
        return "".join(out)

    lanes = runners(report)
    failed = sum(1 for b in blocks if not b["passed"])
    block_ms = sum(b["durationMs"] for b in blocks)
    wall_ms = report["wallMs"]
    suite_rows = suites(report)
    facts = [
        ("Gateway build", duration(report["buildSeconds"] * 1000) if report.get("buildSeconds") else "not recorded"),
        ("Suites", f"{len(suite_rows)}" + (f" ({len(report['skipped'])} with nothing to run on this version)" if report.get("skipped") else "")),
        ("Blocks", f"{len(blocks)} ({len(blocks) - failed} passed, {failed} failed)"),
        ("Runners (blocks at the same time, at most)", f"{report['blockParallel']} ({len(lanes)} used)"),
        ("Time running the suites", duration(wall_ms)),
        ("Time of all blocks added up", duration(block_ms)),
    ]
    out.append("| | |\n| --- | --- |\n" + "".join(f"| {k} | {v} |\n" for k, v in facts))
    out.append("\nEach lane is a runner. It runs one block at a time and takes the next waiting block when it "
               "ends the last one. Arrows show the order a runner ran its blocks, not the time scale; each "
               "block shows its time and its start and end, counted from the start of the run. A block's "
               "time includes waiting for its policy's test binary to compile.\n\n")
    out.extend(diagrams(report))

    out.append("#### Time per runner\n\n| Runner | Blocks | Busy | Finished at | Busy share |\n| ---: | ---: | ---: | ---: | ---: |\n")
    for number, lane in lanes:
        busy, finished = lane_totals(lane)
        share = f"{round(100 * busy / finished)}%" if finished else ""
        out.append(f"| {number} | {len(lane)} | {duration(busy)} | {duration(finished)} | {share} |\n")

    out.append("\n<details>\n<summary>Time per suite</summary>\n\n"
               "| Policy | Result | Blocks | Wall time | Blocks added up | Slowest block | Compile |\n"
               "| --- | --- | ---: | ---: | ---: | --- | ---: |\n")
    for r in suite_rows:
        result = "✅" if not r["failed"] else f"❌ {r['failed']} failed"
        slowest = f"{r['slowest']['block']} ({duration(r['slowest']['durationMs'])})"
        compile_time = duration(r["compileMs"]) if r["compileMs"] is not None else ""
        out.append(f"| {r['policy']} | {result} | {r['blocks']} | {duration(r['wallMs'])} | "
                   f"{duration(r['blockMs'])} | {slowest} | {compile_time} |\n")
    out.append("\n</details>\n")
    return "".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", required=True, type=Path, help="the timeline JSON written by run-suites")
    args = parser.parse_args(argv)
    try:
        print(render(json.loads(args.input.read_text(encoding="utf-8"))))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"### Integration suite timing\n\nNo timing is available: {error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
