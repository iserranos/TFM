# -*- coding: utf-8 -*-
import argparse

import sys
import tempfile

from scapy import all as scapy

def tcp(data):
    pass

def udp(data):
    pass

def icmp(data):
    pass

def arp(data):
    pass


def magic(file, protocol):
    """parse_config"""

    f = tempfile.SpooledTemporaryFile()

    with open(file, 'rb') as e:
        data = e.read()
        f.write(data) # Comprimir
        f.seek(0)
        e.close()

    if protocol is 'tcp':
        tcp(f)
    elif protocol is 'udp':
        udp(f)
    elif protocol is 'icmp':
        icmp(f)
    elif protocol is 'arp':
        arp(f)
    else:
        print('Protocol not valid!')


def main():
    """main"""

    parser = argparse.ArgumentParser(
        description='Client')
    parser.add_argument('-f', action='store', dest='file',
                        default=None, help='File to exfiltrate (eg. "-f /etc/passwd")')
    parser.add_argument('-p', action='store', dest='protocol',
                        default=None, help='Protocol to use (eg. "-p tcp,icmp")')

    results = parser.parse_args()

    if results.file is None & results.proto is None:
        print('Specify a configuration file!')
        parser.print_help()
        sys.exit(-1)

    magic(file=results.file, protocol=results.proto)


if __name__ == '__main__':
    main()
