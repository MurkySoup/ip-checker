#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ip-finder, version 0.3.2 (do not distribute) - find an given address within a given cidr
by rick pelletier (galiagante@gmail.com) - 04 august 2022
last update: 05 august 2022

example usage:

# ./ip-checker.py --cidr "2c0f:f248::/32" --addr "2c0f:f248:ffff:ffff:ffff:ffff:ffff:abcd"
# ./ip-checker.py --cidr "192.168.1.0/24" --addr "192.168.1.5"

features:
- compatible with ipv4 or ipv6 inputs
- will return (standard) exit values of '0' if true/success or '1' if false/fail
- silent mode will give no output, yeilding only exit codes
"""

import sys
import ipaddress
import argparse


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('-c', '--cidr', type=str, required=True, help='CIDR against which to test')
  parser.add_argument('-a', '--addr', type=str, required=True, help='IP address to evaluate')
  parser.add_argument('-s', '--silent', required=False, action='store_false', help='Silent output mode')
  args = parser.parse_args()

  # validate given cidr and begin calculations
  try:
    ipn = ipaddress.ip_network(args.cidr)
    value_range = ipn.num_addresses
    val = args.cidr.split('/')
    ipa = ipaddress.ip_address(val[0])
    start_value = int(ipa)
    end_value = start_value + value_range
  except ValueError:
    if args.silent:
      print('Invalid CIDR given')

    sys.exit(1)

  # validate given target/test ip address and continue calculations
  try:
    test_value = int(ipaddress.ip_address(args.addr))
  except ValueError:
    if args.silent:
      print('Invalid IP address given')

    sys.exit(1)

  # a simple arithmetic check will answer the question
  if start_value <= test_value and test_value <= end_value:
    if args.silent:
      print('Address is within CIDR')
    sys.exit(0)
  else:
    if args.silent:
      print('Address is NOT within CIDR')
    sys.exit(1)

  sys.exit(0)
else:
  sys.exit(1)

# end of script
