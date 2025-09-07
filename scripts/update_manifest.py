#!/usr/bin/env python3
import os
import json

def main():
    entries = []
    for root, _, files in os.walk('cvrf'):
        for name in files:
            if not name.endswith('.json') or name == 'manifest.json':
                continue
            path = os.path.relpath(os.path.join(root, name), 'cvrf')
            entries.append(path.replace('\\', '/'))
    entries.sort()
    with open('cvrf/manifest.json', 'w', encoding='utf-8') as f:
        json.dump(entries, f, separators=(',', ':'))
        f.write('\n')
    print(f'Wrote {len(entries)} entries to cvrf/manifest.json')

if __name__ == '__main__':
    main()
