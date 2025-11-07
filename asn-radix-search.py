#!/usr/bin/env python3

"""
ASN-Radix-Search, Version 1.1-Beta (Do Not Distribute)
Match a (very?) large number of IP addreses against a set of (large?) CIDR's
assigned to a given ASN.

By Rick Pelletier (galiagante@gmail.com) - 04 November 2025
Last Update: 07 November 2025

Usage:
# ./asn-radix-search.py [ASN Number] [IP Address List File]
# ./asn-radix-search.py AS15169 big_ip_list.txt

Linter: ruff check asn-radix-search.py --extend-select F,B,UP
"""

import argparse
import radix
import sys
import os

# --- Constants ---
# Using a stable, public source for BGP/ASN data (e.g., Team Cymru's API)
# The whois.radb.net server allows querying for CIDRs associated with an ASN origin.
WHOIS_RADB_URL = "http://whois.radb.net:43"

def load_ips_from_file(filepath: str) -> list[str]:
    """Reads IP addresses from a file, one per line."""
    if not os.path.exists(filepath):
        print(f"Error: IP list file not found at '{filepath}'")
        sys.exit(1)

    print(f"Loading IPs from {filepath}...")

    with open(filepath) as f:
        # Filter out comments (#) and empty lines
        ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    print(f"Loaded {len(ips)} IP addresses.")

    return ips

def fetch_cidrs_for_asn(asn: str) -> list[str]:
    """
    Fetches the IPv4 and IPv6 CIDR prefixes announced by a given ASN
    using a WHOIS query over HTTP (Team Cymru/RADB style).

    Note: This is a simplified approach. For production, consider dedicated APIs.
    """
    # Ensure ASN format is correct (e.g., AS15169)
    if not asn.upper().startswith('AS'):
        asn = f"AS{asn}"

    print(f"Attempting to fetch CIDRs for ASN {asn}...")

    # Query string for RADB/Team Cymru style lookup: '-i origin <ASN>'
    query = f"-i origin {asn}\r\n"

    try:
        """
        We simulate the WHOIS query using a simple socket connection or a client if
        available, but for a self-contained script, a simple GET/POST to a proxy
        service is safer unless running a dedicated WHOIS client. For robust Python
        code, we'll use a widely available REST API (like the unofficial RADB mirror
        via a free tool or a simple WHOIS proxy). A common, reliable programmatic
        method is direct WHOIS on port 43, but using a library or a proxy API is often
        easier in Python:

        Using a direct WHOIS socket connection (requires manual implementation of
        netcat/socket logic) OR, for a simple HTTP call that returns CIDRs (e.g., using
        a free API mirror):

        We will use the direct WHOIS query method on port 43 via a simple utility (like
        whois.radb.net) that allows HTTP to simplify the Python code slightly for this
        demo:

        NOTE: Standard requests is not ideal for port 43 WHOIS. We'll simulate a fetch
        using a simple public API for better reliability in a script environment. Let's
        use a public API known for ASN data like the 'ipinfo.io' command-line
        equivalent or the simpler HackerTarget API for demonstration purposes.

        --- Using HackerTarget (Free tier limits apply) for demonstration ---
        The service returns multiple CIDRs in an HTML table or structured API, but here
        we'll use the raw WHOIS-like approach which is more aligned with ASN data
        sources.

        Alternative: whois.radb.net query via 'socket' (more direct but non-HTTP):
        """
        import socket
        cidrs = []

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(("whois.radb.net", 43))
            s.sendall(query.encode('utf-8'))

            response = b''

            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break

                response += chunk

            # Parse the response for 'route:' (IPv4) and 'route6:' (IPv6)
            for line in response.decode('utf-8', errors='ignore').splitlines():
                if line.strip().startswith('route:') or line.strip().startswith('route6:'):
                    # Extract the CIDR value from the line
                    parts = line.split()

                    if len(parts) > 1:
                        cidrs.append(parts[1].strip())

        if not cidrs:
            print(f"Warning: Could not retrieve CIDRs for {asn}. Check the ASN or API access.")

            return []

        print(f"Successfully retrieved {len(cidrs)} CIDRs for {asn}.")

        return cidrs

    except OSError as e:
        print(f"Connection Error fetching CIDRs for ASN {asn}: {e}")
        print("Tip: Ensure your network allows outbound connections to port 43.")

        return []
    except Exception as e:
        print(f"An unexpected error occurred during CIDR fetch: {e}")

        return []

def find_matching_ips_radix(ips: list[str], cidrs: list[str]) -> list[tuple[str, str]]:
    """
    Builds a Radix Tree from CIDRs and checks IP addresses for membership.
    """

    # 1. Build the Radix Tree
    print("\nBuilding Radix Tree from fetched CIDR list...")
    rt = radix.Radix()
    inserted_count = 0

    for cidr in cidrs:
        try:
            rt.add(cidr)
            inserted_count += 1
        except Exception:
            # Skip invalid CIDR formats or non-IP strings
            continue

    print(f"Successfully loaded {inserted_count} CIDRs into the tree.")

    matched_ips = []

    # 2. Perform the Highly Efficient Lookup
    print("Starting efficient IP lookup...")
    for ip_str in ips:
        node = rt.search_best(ip_str)

        if node:
            matched_ips.append((ip_str, node.prefix))

    return matched_ips

# --- Main Execution Block ---

def main():
    """
    if len(sys.argv) != 3:
        print("Usage: python your_script_name.py <ASN_Number> <IP_List_File>")
        print("Example: python script.py AS15169 ip_list.txt")
        sys.exit(1)

    target_asn = sys.argv[1]
    ip_file = sys.argv[2]
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('--asn', '-a', type=str, required=True)
    parser.add_argument('--file', '-f', type=str, required=True)
    args = parser.parse_args()

    target_asn = args.asn
    ip_file = args.file

    # 1. Load IP List from File
    ip_addresses = load_ips_from_file(ip_file)

    if not ip_addresses:
        print("Exiting due to empty IP list.")

        return

    # 2. Fetch CIDR List for ASN
    cidr_list = fetch_cidrs_for_asn(target_asn)

    if not cidr_list:
        print("Exiting due to empty CIDR list.")

        return

    # 3. Perform Radix Tree Comparison
    results = find_matching_ips_radix(ip_addresses, cidr_list)

    # 4. Display Results
    print("\n" + "="*50)
    print(f"RESULTS: IPs from '{ip_file}' matching ASN {target_asn}")
    print("="*50)

    if results:
        print("\nMatched IPs:")

        for ip, cidr in results:
            print(f"  IP: {ip} matches CIDR: {cidr}")

        print("\nSummary:")
        print(f"Total IPs checked: {len(ip_addresses)}")
        print(f"Total matches found: {len(results)}")
    else:
        print("No matches found between the IP list and the target ASN's networks.")

if __name__ == "__main__":
    main()

# end of script
