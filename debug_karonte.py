#!/usr/bin/env python3
import json
import sys

config_file = sys.argv[1] if len(sys.argv) > 1 else "config/tai/Zyxel_WX3100.json"

print(f"Loading config: {config_file}")
config = json.load(open(config_file))

print("\nOriginal config:")
for k, v in config.items():
    print(f"  {k}: {v} (type: {type(v).__name__}, truthy: {bool(v)})")

# Simulate what Karonte does
filtered_config = dict((k, v) for k, v in config.items() if v)

print("\nFiltered config:")
for k, v in filtered_config.items():
    print(f"  {k}: {v}")

print("\nMissing after filter:")
for k in config:
    if k not in filtered_config:
        print(f"  {k}: {config[k]}")

# Check border_bins
border_bins = [str(x) for x in config['bin']] if 'bin' in config else []
print(f"\nBorder bins: {border_bins}")

# Check if files exist
import os
for b in border_bins:
    exists = os.path.exists(b)
    print(f"  {b}: exists={exists}")
    if exists:
        print(f"    size: {os.path.getsize(b)} bytes")
