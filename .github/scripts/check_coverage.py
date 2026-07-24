#!/usr/bin/env python3
"""Fail CI if any *production* source line is uncovered (lcov `DA:n,0`), unless
that line is annotated `// cov:unreachable` — a deliberately-unreachable
defensive guard kept for defence-in-depth (see CLAUDE.md coverage standard).

Only files under `src/` are gated, and within them only lines that are NOT
inside a `#[cfg(test)] mod tests { ... }` block (those assertion arms only run
on test failure and are not production code).

Usage: check_coverage.py lcov.info
"""
import sys
import re
from pathlib import Path

GATED_PREFIX = "src/"
MARKER = "// cov:unreachable"


def test_mod_line_ranges(path: Path):
    """1-based line numbers that fall inside a `#[cfg(test)]` module."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    in_test = False
    depth = 0
    ranges = set()
    pending = False
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not in_test and stripped.startswith("#[cfg(test)]"):
            pending = True
            continue
        if pending and stripped.startswith("mod "):
            in_test = True
            pending = False
            depth = line.count("{") - line.count("}")
            ranges.add(i)
            continue
        if in_test:
            ranges.add(i)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                in_test = False
    return ranges


def gated_rel(sf_path: str):
    """Return the `src/...` relative path if this SF is a gated production file."""
    idx = sf_path.find(GATED_PREFIX)
    if idx == -1:
        return None
    return sf_path[idx:]


def main(lcov_path):
    text = Path(lcov_path).read_text(encoding="utf-8", errors="replace")
    failures = []
    cur_file = None
    src_lines = {}
    test_ranges = {}
    for raw in text.splitlines():
        if raw.startswith("SF:"):
            cur_file = raw[3:].strip()
            continue
        if raw.startswith("DA:") and cur_file:
            rel = gated_rel(cur_file)
            if rel is None:
                continue  # not a gated production file
            m = re.match(r"DA:(\d+),(\d+)", raw)
            if not m:
                continue
            lineno, hits = int(m.group(1)), int(m.group(2))
            if hits != 0:
                continue
            fpath = Path(cur_file)
            if not fpath.exists():
                continue
            if fpath not in src_lines:
                src_lines[fpath] = fpath.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                test_ranges[fpath] = test_mod_line_ranges(fpath)
            if lineno in test_ranges[fpath]:
                continue  # test-module line, not production
            source = (
                src_lines[fpath][lineno - 1] if lineno - 1 < len(src_lines[fpath]) else ""
            )
            if MARKER in source:
                continue  # deliberately-unreachable, annotated
            failures.append(f"{rel}:{lineno}: {source.strip()}")

    if failures:
        print("Uncovered production lines (not annotated // cov:unreachable):")
        for f in failures:
            print(f"  {f}")
        sys.exit(1)
    print("Coverage gate: all production lines covered (or annotated unreachable).")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "lcov.info")
