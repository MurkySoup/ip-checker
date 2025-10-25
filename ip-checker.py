#!/usr/bin/env python3

"""
IP Checker, Version 1.0-Beta (Do Not Distribute)
Find a given address within a given CIDR
By Rick Pelletier (galiagante@gmail.com) - 04 August 2022
Last Update: 25 October 2025

The script accepts a CIDR string and an IPv4 (or IPv6) address from the command
line and reports whether the address is in the block.  It can operate in a
"silent" mode where no output is produced and the exit status is the only signal
to the caller.

Example usage:

# ./ip-checker.py --cidr "2c0f:f248::/32" --addr "2c0f:f248:ffff:ffff:ffff:ffff:ffff:abcd"
# ./ip-checker.py --cidr "192.168.1.0/24" --addr "192.168.1.5"

For reference - RFC-1918 Reserved Networks:
- Class A: 10.0.0.0    - 10.255.255.255  -> 10.0.0.0/8
- Class B: 172.16.0.0  - 172.31.255.255  -> 172.16.0.0/12
- Class C: 192.168.0.0 - 192.168.255.255 -> 192.168.0.0/16
- Note: Class C Reserved networks are typically used as /24 subnets

Linter: ruff check ip-checker-new.py --extend-select F,B,UP
"""

from __future__ import annotations
import argparse
import sys
import ipaddress

# --------------------------------------------------------------------------- #
# Core helpers
# --------------------------------------------------------------------------- #

def validate_cidr(cidr: str) -> ipaddress.IPv4Network:
    """
    Parse *cidr* into an :class:ipaddress.IPv4Network instance.

    Parameters
    ----------
    cidr : str
        The CIDR string to validate, e.g. "192.168.0.0/24".

    Returns
    -------
    ipaddress.IPv4Network
        The parsed network.

    Raises
    ------
    ValueError
        If the supplied string is not a valid IPv4 CIDR.
    """
    try:
        return ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise ValueError(exc) from exc


def validate_address(addr: str) -> ipaddress.IPv4Address:
    """
    Parse *addr* into an :class:ipaddress.IPv4Address instance.

    Parameters
    ----------
    addr : str
        The IPv4 address string to validate, e.g. "192.168.0.42".

    Returns
    -------
    ipaddress.IPv4Address
        The parsed address.

    Raises
    ------
    ValueError
        If the supplied string is not a valid IPv4 address.
    """
    try:
        return ipaddress.ip_address(addr)
    except ValueError as exc:
        raise ValueError(exc) from exc


def is_address_in_cidr(network: ipaddress.IPv4Network,
                       address: ipaddress.IPv4Address) -> bool:
    """
    Determine whether *address* belongs to *network*.

    Parameters
    ----------
    network : ipaddress.IPv4Network
        The network to test against.
    address : ipaddress.IPv4Address
        The address to test.

    Returns
    -------
    bool
        True if *address* is inside *network*, otherwise False.
    """
    return address in network

# --------------------------------------------------------------------------- #
# Command‑line handling
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    """
    Construct the :class:argparse.ArgumentParser for this script.

    Returns
    -------
    argparse.ArgumentParser
        The fully configured parser.
    """
    parser = argparse.ArgumentParser(
        description="Check if an IPv4 or IPv6 address lies inside a given CIDR block."
    )
    parser.add_argument(
        "-c",
        "--cidr",
        required=True,
        help="CIDR block to test against (e.g. 192.168.0.0/24)",
    )
    parser.add_argument(
        "-a",
        "--addr",
        required=True,
        help="IPv4 address to evaluate (e.g. 192.168.0.1)",
    )
    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Do not print any output – only the exit status indicates the result",
    )
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Parse command‑line arguments.

    Parameters
    ----------
    argv : list[str] | None, optional
        The list of arguments to parse.  If None (the default) the arguments
        are taken from sys.argv[1:].

    Returns
    -------
    argparse.Namespace
        The parsed arguments.

    Raises
    ------
    SystemExit
        If the user supplied invalid options.
    """
    parser = build_parser()
    return parser.parse_args(argv)

# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> None:
    """
    The script’s main routine.

    Parameters
    ----------
    argv : list[str] | None, optional
        Arguments to parse.  If None the real sys.argv are used.

    Exits
    ------
    int
        Exit code 0 if the address is inside the CIDR, 1 otherwise.  In silent
        mode the exit code is still returned; no output is printed.
    """
    try:
        args = parse_args(argv)
        network = validate_cidr(args.cidr)
        address = validate_address(args.addr)
        inside = is_address_in_cidr(network, address)
    except (ValueError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)

    if not args.silent:
        print(
            "Address is within CIDR" if inside else "Address is NOT within CIDR"
        )

    # The exit status encodes the result for scripts / CI pipelines
    sys.exit(0 if inside else 1)

# --------------------------------------------------------------------------- #
# Standard module guard
# --------------------------------------------------------------------------- #

if __name__ == "__main__":          # pragma: no cover
    main()

# end of script
