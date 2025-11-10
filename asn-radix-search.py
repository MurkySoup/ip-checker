#!/usr/bin/env python3

"""
ASN-Radix-Search, Version 1.1-Refactor (Do Not Distribute)

Matches a (very?) large number of IP addresses against a set of (large?) CIDRs
assigned to a given ASN.

By Rick Pelletier (galiagante@gmail.com) - Refactor 10 November 2025

Usage examples:
  # fetch CIDRs for ASN and test ips in file:
  ./asn_radix_search.py --asn AS15169 --file big_ip_list.txt

  # use a CIDR list provided by user (one CIDR per line) instead of fetching:
  ./asn_radix_search.py --asn AS15169 --file big_ip_list.txt --cidrs-file my_cidrs.txt

Notes:
- If --cidrs-file is present, the script will use those CIDRs. The --asn argument
  is preserved to keep compatibility with prior behaviour and for labeling only.
- Requires `py-radix` (import name `radix`) and Python 3.11+.

Linter: ruff check asn-radix-search-dev.py --extend-select F,B,UP
"""

from __future__ import annotations
import argparse
import ipaddress
import os
import re
import socket
from collections.abc import Sequence

try:
    import radix  # py-radix package
except Exception:  # pragma: no cover - dependency-level handling
    print("Required dependency 'radix' is missing. Install with: pip install py-radix")

    raise

# Constants
WHOIS_RADB_HOST = "whois.radb.net"
WHOIS_RADB_PORT = 43
SOCKET_TIMEOUT_SEC = 10
VALID_CIDR_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$|^[0-9a-fA-F:]+/[0-9]{1,3}$")

# --- Utility functions ---

def read_lines_strip(path: str, comment_prefix: str = "#") -> list[str]:
    """
    Read file lines, strip whitespace, ignore blank lines and lines that start
    with comment_prefix.

    Args:
        path: Path to the file.
        comment_prefix: Prefix that denotes a comment line (default '#').

    Returns:
        List of cleaned lines.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")

    lines: list[str] = []

    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            if line.startswith(comment_prefix):
                continue
            lines.append(line)

    return lines

def load_ips_from_file(filepath: str) -> list[str]:
    """
    Load IP addresses from a file (one per line). Strips comments and blank lines.

    Args:
        filepath: Path to IP list file.

    Returns:
        List of IP string values.
    """
    lines = read_lines_strip(filepath)
    # Minimal validation: ensure lines look like IPv4 or IPv6 addresses
    ips: list[str] = []

    for ln in lines:
        try:
            # ipaddress will normalize/validate
            ipaddress.ip_address(ln)
            ips.append(ln)
        except ValueError:
            # Skip lines that don't parse as IP addresses
            continue

    return ips

def load_cidrs_from_file(filepath: str) -> list[str]:
    """
    Load CIDRs from a file (one CIDR per line). Validates using ipaddress module.

    Args:
        filepath: Path to CIDR list file.

    Returns:
        List of CIDR strings in canonical form.
    """
    raw = read_lines_strip(filepath)
    cidrs: list[str] = []

    for item in raw:
        # quick regex filter to avoid heavy exception costs for obviously wrong lines
        if not VALID_CIDR_REGEX.match(item):
            # still try ipaddress — it gives better errors for weird but valid inputs
            try:
                # Try to interpret as network (this will raise on invalid)
                net = ipaddress.ip_network(item, strict=False)
                cidrs.append(str(net))
                continue
            except Exception:
                # skip invalid entries
                continue
        try:
            net = ipaddress.ip_network(item, strict=False)
            cidrs.append(str(net))
        except Exception:
            # skip invalid entries
            continue

    return cidrs

def fetch_cidrs_for_asn(asn: str) -> list[str]:
    """
    Fetch route/route6 entries via WHOIS from whois.radb.net for the given ASN.

    Args:
        asn: ASN as string (e.g., "AS15169" or "15169").

    Returns:
        List of CIDR strings (may be empty on error).
    """
    if not asn:
        return []

    if not asn.upper().startswith("AS"):
        asn = f"AS{asn}"

    query = f"-i origin {asn}\r\n"

    try:
        with socket.create_connection((WHOIS_RADB_HOST, WHOIS_RADB_PORT), timeout=SOCKET_TIMEOUT_SEC) as s:
            s.sendall(query.encode("utf-8"))
            chunks = []
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
            resp_bytes = b"".join(chunks)
    except OSError:
        # upstream/network error — caller will decide how to handle empty list

        return []

    text = resp_bytes.decode("utf-8", errors="ignore")
    cidrs: list[str] = []

    # look for lines like: "route:      1.2.3.0/24" or "route6:     2001:db8::/32"
    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        # Common format: "route:" or "route6:" followed by CIDR
        if line.startswith("route:") or line.startswith("route6:"):
            parts = line.split()

            if len(parts) >= 2:
                candidate = parts[1].strip()
                try:
                    net = ipaddress.ip_network(candidate, strict=False)
                    cidrs.append(str(net))
                except Exception:
                    # ignore invalid entries
                    continue
        # Some servers reply with "origin: ASXXXXX" lines; ignore them.
    # Deduplicate while preserving order
    seen = set()
    uniq: list[str] = []

    for c in cidrs:
        if c not in seen:
            seen.add(c)
            uniq.append(c)

    return uniq

def build_radix_from_cidrs(cidrs: Sequence[str]) -> radix.Radix:
    """
    Build a radix.Radix tree and load CIDRs into it.

    Args:
        cidrs: Iterable of CIDR strings.

    Returns:
        A radix.Radix instance populated with the networks.
    """
    rt = radix.Radix()

    for cidr in cidrs:
        try:
            rt.add(cidr)
        except Exception:
            # skip invalid or unsupported entries
            continue

    return rt

def find_matching_ips_radix(ips: Sequence[str], cidrs: Sequence[str]) -> list[tuple[str, str]]:
    """
    Given a list of IPs and CIDRs, build a radix tree and return pairs of (ip, matching_cidr).

    Args:
        ips: Iterable of IP address strings.
        cidrs: Iterable of CIDR strings.

    Returns:
        List of tuples (ip, matched_cidr).
    """
    rt = build_radix_from_cidrs(cidrs)
    matched: list[tuple[str, str]] = []

    for ip_str in ips:
        try:
            # validate IP formatting once (avoids silent failures)
            ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        node = rt.search_best(ip_str)

        if node:
            # .prefix is the stored prefix string in py-radix
            matched.append((ip_str, node.prefix))

    return matched


# --- CLI / Main flow ---

def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """
    Parse command line arguments.

    Args:
        argv: Optional sequence of arguments (for testing).

    Returns:
        argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description="Efficiently match IPs to CIDRs using a Radix tree."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--asn",
        "-a",
        help="Target ASN (e.g. AS15169 or 15169)"
    )
    group.add_argument(
        "--cidr-file",
        "-c",
        help="Path to a file containing CIDRs (one per line)."
    )
    parser.add_argument(
        "--ip-file",
        "-i",
        required=True,
        help="Path to file containing IP addresses (one per line)."
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output."
    )

    return parser.parse_args(argv)

def main(argv: Sequence[str] | None = None) -> int:
    """
    Main entry point.

    Returns:
        Exit code (0 success, non-zero error).
    """
    args = parse_args(argv)

    if args.verbose:
        print("Verbose mode enabled.")
        print(f"Args: asn={args.asn}, ip_file={args.ip_file}, cidr_file={args.cidr_file}")

    # 1. Load IPs
    try:
        ip_addresses = load_ips_from_file(args.ip_file)
    except FileNotFoundError as fnf:
        print(f"Error: {fnf}")

        return 2
    except Exception as exc:
        print(f"Unexpected error loading IP file '{args.ip_file}': {exc}")

        return 3

    if not ip_addresses:
        print("No valid IP addresses loaded; exiting.")

        return 0

    # 2. Determine CIDR source: user-supplied file or WHOIS fetch
    cidr_list: list[str] = []

    if args.cidr_file:
        try:
            cidr_list = load_cidrs_from_file(args.cidr_file)

            if args.verbose:
                print(f"Loaded {len(cidr_list)} valid CIDRs from {args.cidr_file}")
        except FileNotFoundError:
            print(f"Error: CIDR file not found: {args.cidr_file}")

            return 4
        except Exception as exc:
            print(f"Unexpected error loading CIDR file '{args.cidr_file}': {exc}")

            return 5

    if not cidr_list:
        # fetch via whois
        cidr_list = fetch_cidrs_for_asn(args.asn)

        if args.verbose:
            print(f"Fetched {len(cidr_list)} CIDRs for ASN {args.asn} (via whois)")

    if not cidr_list:
        print("No CIDRs available for comparison; exiting.")

        return 0

    # 3. Perform comparison
    results = find_matching_ips_radix(ip_addresses, cidr_list)

    # 4. Print results
    sep = "=" * 60
    print("\n" + sep)
    print(f"RESULTS: IPs from '{args.ip_file}' matching CIDR(s)")
    print(sep)

    if results:
        print(f"\nMatched IPs ({len(results)}):")

        for ip, cidr in results:
            print(f"  IP: {ip} matches CIDR: {cidr}")

        print("\nSummary:")
        print(f"  Total IPs checked: {len(ip_addresses)}")
        print(f"  Total matches found: {len(results)}")
    else:
        print("No matches found between the IP list and the target ASN's networks.")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

# end of script
