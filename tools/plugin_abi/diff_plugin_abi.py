#!/usr/bin/env python

import difflib
import argparse
import re
import sys


def lines(path):
    with open(path) as f:
        return f.readlines()


def check_abi_diff(diff):
    old_abi_version = None
    new_abi_version = None
    fields_removed = False

    for line in diff:
        abi_change = re.match(r'^([-+])\s*#define\s+PLUGIN_ABI_VERSION\s+(\d+)', line)
        if abi_change:
            if abi_change.group(1) == '-':
                old_abi_version = int(abi_change.group(2))
            else:
                new_abi_version = int(abi_change.group(2))
            continue

        if line.startswith('-') and line != '--- ':
            fields_removed = True
            continue

    if old_abi_version is not None and new_abi_version is not None:
        if new_abi_version > old_abi_version:
            print('Plugin ABI version bump: old=%d, new=%d' % (old_abi_version, new_abi_version))
            if not fields_removed:
                raise ValueError('Unnecessary ABI version bump')
        else:
            assert new_abi_version != old_abi_version, 'Plugin ABI version diff without actual change: old=%d, new=%d' % (
                old_abi_version, new_abi_version)
            raise ValueError('Plugin ABI version downgrade: old=%d, new=%d' % (old_abi_version, new_abi_version))
    else:
        if fields_removed:
            raise ValueError('Incompatible ABI changes without a version bump')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Diff two plugin ABI definitions')
    parser.add_argument('old', type=argparse.FileType('r'), help='Old ABI definition')
    parser.add_argument('new', type=argparse.FileType('r'), help='New ABI definition')
    args = parser.parse_args()

    old = args.old.readlines()
    new = args.new.readlines()
    diff = [line.strip('\n') for line in
            difflib.unified_diff(old, new, lineterm='', fromfile=args.old.name, tofile=args.new.name)]

    try:
        check_abi_diff(diff)
    except Exception as exc:
        print('ABI compatibility check failed: %s' % exc)
        for line in diff:
            print(line)
        sys.exit(1)
