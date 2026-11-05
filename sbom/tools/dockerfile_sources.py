#!/usr/bin/env python3
"""Print the repository paths a Dockerfile copies into its image.

Reads every ADD/COPY instruction that pulls from the build context (ignores
`--from=` stage copies and remote URLs), expands globs against the repository
root, and prints one path per line. These paths plus the Dockerfile itself are
the "source view" of the deployable.
"""

import argparse
import glob
import os
import re
import shlex
import sys

INSTR = re.compile(r'^\s*(ADD|COPY)\s+(.*)$', re.IGNORECASE)


def parse_sources(dockerfile):
    lines = []
    with open(dockerfile, encoding='utf-8') as f:
        buf = ''
        for raw in f:
            line = raw.rstrip('\n')
            if line.rstrip().endswith('\\'):
                buf += line.rstrip()[:-1] + ' '
                continue
            lines.append(buf + line)
            buf = ''
        if buf:
            lines.append(buf)

    sources = []
    for line in lines:
        m = INSTR.match(line)
        if not m:
            continue
        try:
            tokens = shlex.split(m.group(2), comments=False)
        except ValueError:
            tokens = m.group(2).split()
        args = []
        from_stage = False
        for tok in tokens:
            if tok.startswith('--'):
                if tok.startswith('--from'):
                    from_stage = True
                continue
            args.append(tok)
        if from_stage or len(args) < 2:
            continue
        for src in args[:-1]:
            if re.match(r'^[a-z]+://', src):
                continue
            sources.append(src)
    return sources


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('dockerfile')
    ap.add_argument('--root', default='.', help='build context root (repository root)')
    opts = ap.parse_args()

    root = os.path.abspath(opts.root)
    seen = []
    for src in parse_sources(opts.dockerfile):
        rel = os.path.normpath(src)
        if rel.startswith('..'):
            continue
        matches = sorted(glob.glob(os.path.join(root, rel)))
        if not matches:
            print(f'warning: {opts.dockerfile}: no match for {src}', file=sys.stderr)
        for m in matches:
            relm = os.path.relpath(m, root)
            if relm not in seen:
                seen.append(relm)
    for p in seen:
        print(p)


if __name__ == '__main__':
    main()
