# ip-checker

A simple tool to confirm/deny that a given IP address falls within a given CIDR.

# Description

As IP address spaces are rather large (IPv6 is ridiculously over-sized), iteration over a given CIDR is neither efficient nor even feasible in some cases. Instead, we reduce this problem to a matter of simple, fast arithmetic checks, just as nature intended.

Basic features:
* Compatible with IPv4 or IPV6 inputs.
* Will return (standard) exit values of '0' if true/success or '1' if false/fail.
* Silent mode will give no output, yielding only exit codes.
* Intended for easy inclusion into other scripting frameworks and worflows.

All source code is written for clarity and maintainability and should be mostly self-explanatory.

# Prerequisites

Requires Python 3.x (preferably 3.7+) and uses the following (entirely standard) libraries:
* sys
* ipaddress
* argparse

# Example Usage and Notes

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

# License

This tool is released under the MIT license. See the LICENSE file in this repo for details.

# Built With

* [Python](https://www.python.org) designed by Guido van Rossum

## Author

**Rick Pelletier** - [Gannett Co., Inc. (USA Today Network)](https://www.usatoday.com/)
