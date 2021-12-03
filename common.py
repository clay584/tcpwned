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
    return data.encode("utf-8").strip().hex()


def chunk(data):
    chunk_len = 4
    return [data[i : i + chunk_len] for i in range(0, len(data), chunk_len)]


def deser_data(data):
    bytes_obj = bytes.fromhex(data)
    return bytes_obj.decode("utf-8")
