"""Command-line interface for keyshape."""

import argparse
import json
import sys

import scanner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keyshape",
        description="Scan a codebase for secret-shaped strings.",
    )
    p.add_argument("path", nargs="?", default=".", help="directory or file to scan")
    p.add_argument("--format", choices=("text", "json"), default="text",
                   help="output format (default: text)")
    p.add_argument("--no-fail", action="store_true",
                   help="always exit 0 even when findings exist")
    p.add_argument("--ignore", action="append", default=[],
                   help="additional glob to ignore (repeatable)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    target = args.path
    import os
    if os.path.isfile(target):
        # scan single file by treating parent as root with filter
        root = os.path.dirname(os.path.abspath(target)) or "."
        findings = scanner.scan_file(target, os.path.basename(target))
    else:
        findings = scanner.scan(target, extra_ignore=args.ignore)

    if args.format == "json":
        print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    else:
        if not findings:
            print("keyshape: no findings")
        else:
            for f in findings:
                print(f"{f['file']}:{f['line']}: [{f['pattern']}] {f['snippet']}")
            print(f"\nkeyshape: {len(findings)} finding(s)")

    if findings and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
