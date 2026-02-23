#!/usr/bin/env python3
"""
Debug script to understand why HTTP strings are not being discovered in zhttpd
"""
import angr
import sys
from tool.taint_analysis.utils import get_addrs_similar_string, get_string

def debug_string_search(binary_path, keywords):
    """
    Debug why keywords are not found in binary
    """
    print(f"=== Analyzing {binary_path} ===\n")

    # Load binary
    print("[1] Loading binary with angr...")
    try:
        p = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
        print(f"    ✓ Loaded: {p.arch.name} binary")
        print(f"    Entry: {hex(p.entry)}")
        print(f"    Base: {hex(p.loader.main_object.min_addr)}")
    except Exception as e:
        print(f"    ✗ Failed to load: {e}")
        return

    # Check if binary has strings section
    print("\n[2] Checking sections...")
    for section in p.loader.main_object.sections:
        if 'str' in section.name.lower() or 'rodata' in section.name.lower():
            print(f"    ✓ {section.name}: {hex(section.vaddr)} (size: {section.memsize})")

    # Try to find raw strings in binary
    print("\n[3] Searching for raw strings in binary...")
    all_strings = []
    try:
        # Get all strings from the binary (read-only sections)
        for section in p.loader.main_object.sections:
            if section.is_readable and not section.is_writable:
                try:
                    data = p.loader.memory.load(section.vaddr, section.memsize)
                    # Find null-terminated strings
                    current_string = b""
                    start_addr = None
                    for i, byte in enumerate(data):
                        if 32 <= byte <= 126:  # Printable ASCII
                            if not current_string:
                                start_addr = section.vaddr + i
                            current_string += bytes([byte])
                        elif byte == 0 and len(current_string) >= 4:
                            string_text = current_string.decode('ascii', errors='ignore')
                            all_strings.append((start_addr, string_text))
                            current_string = b""
                        else:
                            current_string = b""
                except Exception as e:
                    print(f"    ⚠ Error reading section {section.name}: {e}")

        print(f"    Found {len(all_strings)} strings in read-only sections")

        # Check for keywords
        for keyword in keywords:
            matches = [s for s in all_strings if keyword.lower() in s[1].lower()]
            if matches:
                print(f"\n    ✓ Found '{keyword}':")
                for addr, string in matches[:5]:  # Show first 5 matches
                    print(f"      {hex(addr)}: {string[:60]}")
                if len(matches) > 5:
                    print(f"      ... and {len(matches) - 5} more")
            else:
                print(f"\n    ✗ No matches for '{keyword}'")

    except Exception as e:
        print(f"    ✗ Error: {e}")
        import traceback
        traceback.print_exc()

    # Now test with angr's get_addrs_similar_string
    print("\n[4] Testing with Karonte's get_addrs_similar_string()...")
    for keyword in keywords:
        try:
            addrs = get_addrs_similar_string(p, keyword)
            if addrs:
                print(f"    ✓ '{keyword}': found {len(addrs)} address(es)")
                for addr in addrs[:3]:
                    try:
                        string_val = get_string(p, addr, extended=False)
                        print(f"      {hex(addr)}: {string_val}")
                    except:
                        print(f"      {hex(addr)}: (couldn't retrieve string)")
            else:
                print(f"    ✗ '{keyword}': NOT FOUND")
        except Exception as e:
            print(f"    ✗ '{keyword}': Error - {e}")

    # Check what get_addrs_similar_string actually does
    print("\n[5] Understanding get_addrs_similar_string behavior...")
    print("    Checking if it uses case-sensitive matching...")
    test_keywords = [
        "QUERY_STRING",
        "query_string",
        "Query_String",
        "username",
        "USERNAME",
    ]
    for test_kw in test_keywords:
        addrs = get_addrs_similar_string(p, test_kw)
        print(f"    '{test_kw}': {len(addrs)} match(es)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_string_discovery.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]

    # These are the default keywords from Karonte
    default_keywords = [
        'QUERY_STRING', 'username', 'http_', 'REMOTE_ADDR',
        'boundary=', 'REQUEST_METHOD', 'REQUEST_URI',
        'CONTENT_TYPE', 'CONTENT_LENGTH', 'HTTP_COOKIE',
        'HTTP_HOST', 'HTTP_USER_AGENT', 'HTTP_REFERER'
    ]

    debug_string_search(binary_path, default_keywords)
