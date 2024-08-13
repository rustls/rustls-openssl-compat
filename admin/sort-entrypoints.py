#!/usr/bin/env python3

from os import path
import difflib

entries = []
in_entries = False

location = path.join(path.dirname(__file__), '../build.rs')

for line in open(location):
    if in_entries:
        if '];' in line:
            in_entries = False
            continue

        entries.append(line)

    if 'const ENTRYPOINTS:' in line:
        in_entries = True

assert len(entries) != 0
sorted_entries = list(sorted(entries, key=lambda s: s.lower()))

if entries != sorted_entries:
    print('!!! ENTRYPOINTS is not sorted')
    print(''.join(difflib.context_diff(entries, sorted_entries, fromfile='build.rs', tofile='build.rs')))
    exit(1)
