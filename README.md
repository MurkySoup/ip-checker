# ip-checker

Tools to confirm/deny that a given IP address(es) falls within a given CIDR(s).

# Description

As IP address spaces are rather large (IPv6 is ridiculously over-sized), iteration over a given CIDR is neither efficient nor even feasible in some cases. Instead, we reduce this problem to a matter of simple, fast arithmetic checks, just as nature intended.

Basic features:
* Compatible with IPv4 or IPv6 inputs (will auto-detect, even).
* Will return (standard) exit values of '0' if true/success or '1' if false/fail.
* Silent mode will give no output, yielding only exit codes.
* Intended for easy inclusion into other scripting frameworks and worflows.

All source code is written for clarity and maintainability and should be mostly self-explanatory.

# Prerequisites

Requires Python 3.x (preferably 3.11+) and uses the following libraries:

* annotations (future)
* argparse
* ipaddress
* os
* re
* socket
* collections.abc

# Single Address Searches

Options:
```
usage: ip-checker.py [-h] -c CIDR -a ADDR [-s]

options:
  -h, --help            show this help message and exit
  -c CIDR, --cidr CIDR  CIDR against which to test
  -a ADDR, --addr ADDR  IP address to evaluate
  -s, --silent          Silent output mode
```

Checking IPv6 Addresses:
```
# ./ip-checker.py --cidr "2c0f:f248::/32" --addr "2c0f:f248:ffff:ffff:ffff:ffff:ffff:abcd; echo $?;"
Address is within CIDR
0
```
Note: As IPV6 addressing can use more flexible notation, this has been included as a feature. Use of both 'exploded' and 'compressed' formats are acceptible.

Checking IPv4 Addresses":
```
# ./ip-checker.py --cidr "192.168.1.0/24" --addr "192.168.2.5"; echo $?;
Address is NOT within CIDR
1
```

Note: Use "silent mode" will return only an exit value without output to stdout.

# Bulk Searches

Facing the issue of matching a potentially large number of IP addresses against a set of CIDR's, a search tool (using radix-tree data search techniques) has been written to answer this challenge efficiently.

```
usage: asn-radix-search-dev.py [-h] (--asn ASN | --cidr-file CIDR_FILE) --ip-file IP_FILE [--verbose]

Efficiently match IPs to CIDRs using a Radix tree.

options:
  -h, --help                           show this help message and exit
  --asn ASN, -a ASN                    Target ASN (e.g. AS15169 or 15169)
  --cidr-file CIDR_FILE, -c CIDR_FILE  Path to a file containing CIDRs (one per line).
  --ip-file IP_FILE, -i IP_FILE        Path to file containing IP addresses (one per line).
  --verbose, -v                        Enable verbose output.
```

Example:

```
$ ./asn-radix-search.py --cidr-file cidrs.txt --ip-file addresses.txt

============================================================
RESULTS: IPs from 'addresses.txt' matching CIDR(s)
============================================================

Matched IPs (15):
  IP: 184.75.73.26 matches CIDR: 184.75.73.0/24
  IP: 209.221.34.144 matches CIDR: 209.221.34.128/26
  IP: 209.221.34.151 matches CIDR: 209.221.34.128/26
  IP: 209.97.12.123 matches CIDR: 209.97.12.0/23
  IP: 45.43.109.148 matches CIDR: 45.43.109.128/25
  IP: 45.43.109.187 matches CIDR: 45.43.109.128/25
  IP: 45.43.109.229 matches CIDR: 45.43.109.128/25
  IP: 50.212.215.121 matches CIDR: 50.212.215.0/24
  IP: 50.212.215.153 matches CIDR: 50.212.215.0/24
  IP: 66.76.178.10 matches CIDR: 66.76.178.0/24
  IP: 66.76.178.249 matches CIDR: 66.76.178.0/24
  IP: 66.76.178.72 matches CIDR: 66.76.178.0/24
  IP: 66.76.178.78 matches CIDR: 66.76.178.0/24
  IP: 66.76.178.94 matches CIDR: 66.76.178.0/24
  IP: 96.245.46.3 matches CIDR: 96.245.46.0/24

Summary:
  Total IPs checked: 21
  Total matches found: 15
```

This utility does not have a 'silent" mode. But will return various exit values.

# License

This tool is released under the MIT license. See the LICENSE file in this repo for details.

# Built With

* [Python](https://www.python.org) designed by Guido van Rossum

## Author

**Rick Pelletier** - [Gannett Co., Inc. (USA Today Network)](https://www.usatoday.com/)
