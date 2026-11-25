#!/usr/bin/env python3

from os import path
import difflib

location = path.join(path.dirname(__file__), "../build.rs")

# name of each `const ENTRYPOINTS_*` list -> its lines
lists = {}
current = None

for line in open(location):
    if current is not None:
        if "];" in line:
            current = None
            continue

        lists[current].append(line)

    if line.startswith("const ENTRYPOINTS") and line.rstrip().endswith("&["):
        current = line.split(":")[0].removeprefix("const ")
        lists[current] = []

assert len(lists) != 0
failed = False

for name, entries in lists.items():
    sorted_entries = list(sorted(entries, key=lambda s: s.lower()))

    if entries != sorted_entries:
        print(f"!!! {name} is not sorted")
        print(
            "".join(
                difflib.context_diff(
                    entries, sorted_entries, fromfile="build.rs", tofile="build.rs"
                )
            )
        )
        failed = True

if failed:
    exit(1)
