#!/usr/bin/env python3
"""
Standalone angr CFG Testing Script

Purpose: Quickly test if firmware binaries can be analyzed by angr before running full Karonte analysis

Usage:
    python3 test_angr_cfg.py /path/to/binary                    # Test single binary
    python3 test_angr_cfg.py /path/to/firmware/squashfs-root    # Test entire firmware
    python3 test_angr_cfg.py /path/to/binary --timeout 30       # Set 30s timeout
    python3 test_angr_cfg.py /path/to/binary --fast             # Use CFGFast

Author: Karonte User
Version: 1.0
"""

import sys
import os
import time
import signal
import argparse

try:
    import angr
    try:
        version = angr.__version__
        print("[OK] angr version: {}".format(version))
    except AttributeError:
        print("[OK] angr is installed (version unknown)")
except ImportError:
    print("[ERROR] angr is not installed")
    print("Install command: pip3 install angr")
    sys.exit(1)


class TimeoutException(Exception):
    """Timeout exception"""
    pass


def timeout_handler(signum, frame):
    raise TimeoutException("CFG construction timeout")


def test_single_binary(binary_path, timeout=60, use_fast=False, verbose=False):
    """
    Test CFG construction for a single binary

    Args:
        binary_path: Path to binary file
        timeout: Timeout in seconds
        use_fast: Whether to use CFGFast
        verbose: Whether to print detailed info

    Returns:
        (success: bool, elapsed_time: float, error_msg: str, cfg_info: dict)
    """
    if not os.path.exists(binary_path):
        return (False, 0, "File not found: {}".format(binary_path), None)

    if not os.path.isfile(binary_path):
        return (False, 0, "Not a file", None)

    # Check if ELF
    try:
        with open(binary_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'\x7fELF':
                return (False, 0, "Not an ELF binary", None)
    except Exception as e:
        return (False, 0, "Cannot read file: {}".format(e), None)

    start_time = time.time()

    # Set timeout signal
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        if verbose:
            print("  Loading binary: {}".format(binary_path))

        # Load binary
        p = angr.Project(binary_path, auto_load_libs=False)

        if verbose:
            print("  Architecture: {}".format(p.arch.name))
            print("  Entry point: {}".format(hex(p.entry)))

        # Build CFG
        cfg_method = "CFGFast" if use_fast else "CFG"
        if verbose:
            print("  Building {}...".format(cfg_method))

        if use_fast:
            cfg = p.analyses.CFGFast(normalize=True)
        else:
            cfg = p.analyses.CFG(
                collect_data_references=True,
                extra_cross_references=True
            )

        elapsed = time.time() - start_time
        signal.alarm(0)  # Cancel timeout

        # Collect CFG info
        cfg_info = {
            'nodes': len(cfg.model.nodes()),
            'functions': len(cfg.functions),
            'arch': p.arch.name,
            'entry': hex(p.entry),
            'method': cfg_method
        }

        return (True, elapsed, None, cfg_info)

    except TimeoutException:
        signal.alarm(0)
        elapsed = time.time() - start_time
        return (False, elapsed, "TIMEOUT", None)

    except MemoryError:
        signal.alarm(0)
        elapsed = time.time() - start_time
        return (False, elapsed, "OUT_OF_MEMORY", None)

    except Exception as e:
        signal.alarm(0)
        elapsed = time.time() - start_time
        error_msg = "{}: {}".format(type(e).__name__, str(e))
        return (False, elapsed, error_msg, None)


def find_elf_binaries(root_path, max_binaries=None):
    """
    Find all ELF binaries in directory

    Args:
        root_path: Root directory
        max_binaries: Maximum number to return (None=unlimited)

    Returns:
        List of binary file paths
    """
    binaries = []

    # Common binary directories
    search_dirs = [
        'bin', 'sbin', 'usr/bin', 'usr/sbin',
        'usr/local/bin', 'usr/local/sbin'
    ]

    for search_dir in search_dirs:
        full_path = os.path.join(root_path, search_dir)
        if not os.path.isdir(full_path):
            continue

        for filename in os.listdir(full_path):
            file_path = os.path.join(full_path, filename)

            if not os.path.isfile(file_path):
                continue

            # Check if ELF
            try:
                with open(file_path, 'rb') as f:
                    if f.read(4) == b'\x7fELF':
                        binaries.append(file_path)

                        if max_binaries and len(binaries) >= max_binaries:
                            return binaries
            except:
                continue

    return sorted(binaries)


def print_result(binary_name, success, elapsed, error, cfg_info):
    """Print test result"""
    status = "SUCCESS" if success else "FAILED"
    color = "\033[0;32m" if success else "\033[0;31m"
    reset = "\033[0m"

    print("\n{}[{}]{} {} ({:.2f}s)".format(color, status, reset, binary_name, elapsed))

    if success and cfg_info:
        print("  Method: {}".format(cfg_info['method']))
        print("  Architecture: {}".format(cfg_info['arch']))
        print("  CFG Nodes: {}".format(cfg_info['nodes']))
        print("  Functions: {}".format(cfg_info['functions']))
        print("  Entry: {}".format(cfg_info['entry']))
    elif error:
        print("  Error: {}".format(error))


def main():
    parser = argparse.ArgumentParser(
        description='Test if angr CFG construction supports specific firmware binaries',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test single binary
  python3 test_angr_cfg.py /usr/bin/httpd

  # Test entire firmware directory
  python3 test_angr_cfg.py firmware/TP_Link/squashfs-root

  # Use CFGFast (faster but may be less accurate)
  python3 test_angr_cfg.py /usr/bin/httpd --fast

  # Set timeout
  python3 test_angr_cfg.py /usr/bin/httpd --timeout 120

  # Verbose output
  python3 test_angr_cfg.py /usr/bin/httpd -v
        """
    )

    parser.add_argument('path', help='Binary file path or firmware root directory')
    parser.add_argument('--timeout', type=int, default=60,
                       help='CFG construction timeout in seconds (default: 60)')
    parser.add_argument('--fast', action='store_true',
                       help='Use CFGFast instead of standard CFG')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show verbose output')
    parser.add_argument('--max', type=int, default=None,
                       help='Maximum number of binaries to test when scanning directory')

    args = parser.parse_args()

    # Check path
    if not os.path.exists(args.path):
        print("[ERROR] Path does not exist: {}".format(args.path))
        sys.exit(1)

    print("=" * 60)
    print("angr CFG Construction Test")
    print("=" * 60)
    try:
        print("angr version: {}".format(angr.__version__))
    except AttributeError:
        print("angr version: unknown")
    print("CFG method: {}".format('CFGFast' if args.fast else 'CFG (standard)'))
    print("Timeout: {}s".format(args.timeout))
    print("=" * 60)

    # Check if file or directory
    if os.path.isfile(args.path):
        # Single file
        print("\nTesting single binary: {}".format(args.path))

        success, elapsed, error, cfg_info = test_single_binary(
            args.path,
            timeout=args.timeout,
            use_fast=args.fast,
            verbose=args.verbose
        )

        binary_name = os.path.basename(args.path)
        print_result(binary_name, success, elapsed, error, cfg_info)

        if not success:
            print("\nSuggestions:")
            if error == "TIMEOUT":
                print("  1. Increase timeout: --timeout 120")
                print("  2. Use CFGFast: --fast")
                print("  3. Add this binary to Karonte config's angr_explode_bins")
            elif error == "OUT_OF_MEMORY":
                print("  1. Use CFGFast: --fast")
                print("  2. Increase system swap space")
                print("  3. Add this binary to angr_explode_bins")
            else:
                print("  1. Check binary format: file <binary>")
                print("  2. View detailed error: -v")
                print("  3. Add this binary to angr_explode_bins")

        sys.exit(0 if success else 1)

    elif os.path.isdir(args.path):
        # Entire directory
        print("\nScanning firmware directory: {}".format(args.path))

        binaries = find_elf_binaries(args.path, max_binaries=args.max)

        if not binaries:
            print("[ERROR] No ELF binaries found")
            print("\nTip: Ensure path points to firmware root filesystem (squashfs-root)")
            sys.exit(1)

        print("Found {} ELF binaries".format(len(binaries)))

        # Test each binary
        results = []
        failed = []

        for i, binary_path in enumerate(binaries, 1):
            binary_name = os.path.basename(binary_path)
            relative_path = os.path.relpath(binary_path, args.path)

            print("\n[{}/{}] Testing: {}".format(i, len(binaries), relative_path))

            success, elapsed, error, cfg_info = test_single_binary(
                binary_path,
                timeout=args.timeout,
                use_fast=args.fast,
                verbose=args.verbose
            )

            results.append({
                'name': binary_name,
                'path': relative_path,
                'success': success,
                'time': elapsed,
                'error': error,
                'info': cfg_info
            })

            if not success:
                failed.append(binary_name)

            # Brief output
            status = "\033[0;32m[OK]\033[0m" if success else "\033[0;31m[FAIL]\033[0m"
            output_msg = "  {} {:.2f}s".format(status, elapsed)
            if not success:
                output_msg += " - {}".format(error)
            print(output_msg)

        # Summary report
        print("\n" + "=" * 60)
        print("Test Report")
        print("=" * 60)

        success_count = sum(1 for r in results if r['success'])
        fail_count = len(results) - success_count

        print("Total: {}".format(len(results)))
        print("Success: \033[0;32m{}\033[0m".format(success_count))
        print("Failed: \033[0;31m{}\033[0m".format(fail_count))

        if failed:
            print("\nFailed binaries:")
            for r in results:
                if not r['success']:
                    print("  [X] {}".format(r['name']))
                    print("      Path: {}".format(r['path']))
                    print("      Error: {}".format(r['error']))
                    print("      Time: {:.2f}s".format(r['time']))

            # Generate suggested config
            print("\nSuggested Karonte Configuration:")
            print("=" * 60)
            print("Add the following to your config file (config/*.json):")
            print()
            print('{')
            print('    "angr_explode_bins": [')

            # Common binaries to exclude
            common_excludes = [
                "openvpn", "wpa_supplicant", "vpn", "dns",
                "ip", "log", "qemu-arm-static"
            ]

            all_excludes = sorted(set(failed + common_excludes))

            for i, name in enumerate(all_excludes):
                comma = "," if i < len(all_excludes) - 1 else ""
                print('        "{}"{}'.format(name, comma))

            print('    ]')
            print('}')
            print()

            # Test CFGFast
            if not args.fast:
                print("Tip: Try --fast option, some binaries may succeed with CFGFast")

        else:
            print("\n\033[0;32m[SUCCESS] All binaries passed!\033[0m")
            print("Safe to run Karonte analysis")

        # Performance stats
        if success_count > 0:
            avg_time = sum(r['time'] for r in results if r['success']) / success_count
            max_result = max((r for r in results if r['success']), key=lambda x: x['time'])

            print("\nPerformance Statistics:")
            print("  Average CFG build time: {:.2f}s".format(avg_time))
            print("  Slowest: {} ({:.2f}s)".format(max_result['name'], max_result['time']))

        sys.exit(0 if fail_count == 0 else 1)

    else:
        print("[ERROR] Invalid path type")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nUser interrupted")
        sys.exit(1)
    except Exception as e:
        print("\n[ERROR] {}".format(e))
        import traceback
        traceback.print_exc()
        sys.exit(1)
