#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
IP-Finder, Version 0.4 (Do Not Distribute)
Confirms/denies that a given ip address falls within a target ICDR.
By Rick Pelletier (galiagante@gmail.com) - 04 August 2022
Last Update: 01 April 2023

Example usage:

# ./ip-checker.py --cidr "2c0f:f248::/32" --addr "2c0f:f248:ffff:ffff:ffff:ffff:ffff:abcd"
# ./ip-checker.py --cidr "192.168.1.0/24" --addr "192.168.1.5"

Features:
- Compatible with IPv4 or IPv6 inputs.
- Will return (standard) exit values of '0' if true/success or '1' if false/fail.
- Silent mode will give no output, yielding only exit codes.

The changes made to this version are:
1. Reorganizing the code to have a more clear structure, including defining functions for
   validating the CIDR and IP address.
2. Simplifying the calculations for the start and end values of the IP range by using the
   network_address and broadcast_address properties of the 'ipaddress.IPv4Network' and
   'ipaddress.IPv6Network' classes.
3. Simplifying the logic for checking if the IP address is within the CIDR range by using
   the Python comparison operator <=.
4. Removing unnecessary code at the end of the script, where sys.exit(0) was called twice.
"""


import sys
import ipaddress
import argparse


def validate_cidr(cidr):
    try:
        ipn = ipaddress.ip_network(cidr)
        return True, ipn
    except ValueError:
        return False, None


def validate_address(addr):
    try:
        return True, int(ipaddress.ip_address(addr))
    except ValueError:
        return False, None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cidr', type=str, required=True, help='CIDR against which to test')
    parser.add_argument('-a', '--addr', type=str, required=True, help='IP address to evaluate')
    parser.add_argument('-s', '--silent', required=False, action='store_false', help='Silent output mode')
    args = parser.parse_args()

    # validate given cidr and target/test ip address
    cidr_valid, ipn = validate_cidr(args.cidr)
    addr_valid, test_value = validate_address(args.addr)

    if not cidr_valid:
        if args.silent:
            print('Invalid CIDR given')
        sys.exit(1)

    if not addr_valid:
        if args.silent:
            print('Invalid IP address given')
        sys.exit(1)

    # a simple arithmetic check will answer the question
    start_value = int(ipn.network_address)
    end_value = int(ipn.broadcast_address) + 1

    if start_value <= test_value <= end_value:
        if args.silent:
            print('Address is within CIDR')
        sys.exit(0)
    else:
        if args.silent:
            print('Address is NOT within CIDR')
        sys.exit(1)

# end of script
