#!/usr/bin/env python3
# detects single byte xor encoding by searching for the
# encoded MZ, lfanew and PE, then XORs the data and
# uses pefile to extract the decoded executable.
# written quickly/poorly by alexander hanel
# Rewritten for Python 3 by Corey Forman (github.com/digitalsleuth)

import sys
import struct
import re
from io import StringIO
import pefile
import argparse

def get_xor():
    # read file into a bytearray
    byte = bytearray(open(sys.argv[1], "rb").read())
    # for each byte in the file stream, excluding the last 256 bytes
    for i in range(0, len(byte) - 256):
        # KEY ^ VALUE ^ KEY = VALUE; Simple way to get the key
        key = byte[i] ^ ord("M")
        # verify the two bytes contain 'M' & 'Z'
        if chr(byte[i] ^ key) == "M" and chr(byte[i + 1] ^ key) == "Z":
            # skip non-XOR encoded MZ
            if key == 0:
                continue
            # read four bytes into temp, offset to PE aka lfanew
            temp = byte[(i + 0x3C) : (i + 0x3C + 4)]
            # decode values with key
            lfanew = []
            for x in temp:
                lfanew.append(x ^ key)
            # convert from bytearray to int
            pe_offset = struct.unpack("<i", bytearray(lfanew))[0]
            # verify results are not negative or read is bigger than file
            if pe_offset < 0 or pe_offset > len(byte):
                continue
            # verify the two decoded bytes are 'P' & 'E'
            if byte[pe_offset + i] ^ key == ord("P") and byte[
                pe_offset + 1 + i
            ] ^ key == ord("E"):
                print(f" * Encoded PE Found, Key {hex(key)}, Offset {hex(pe_offset)}")
                return (key, i)
    print(" * No encoded PE detected")
    return (None, None)


def getExt(pe):
    if pe.is_dll():
        return "dll"
    if pe.is_driver():
        return "sys"
    if pe.is_exe():
        return "exe"
    return "bin"


def writeFile(count, ext, pe):
    fileName = f"{str(count)}.{ext}"
    try:
        out = open(fileName, "wb")
    except:
        print("\t[FILE ERROR] could not write file")
        sys.exit()
    # remove overlay or junk in the trunk
    out.write(pe.trim())
    out.close()
    print(f" * File {fileName} saved")


def xor_data(key):
    byte = bytearray(open(sys.argv[1], "rb").read())
    temp = ""
    for x in byte:
        temp += chr(x ^ key)
    return temp


def carve(fileH):
    if isinstance(fileH, str):
        fileH = StringIO(fileH)
    c = 1
    # For each address that contains MZ
    for y in [tmp.start() for tmp in re.finditer("\x4d\x5a", fileH.read())]:
        fileH.seek(y)
        try:
            pe = pefile.PE(data=bytearray(fileH.read(), "latin-1"))
        except:
            continue
        # determine file ext
        ext = getExt(pe)
        print(f" * {(ext).upper()} found at offset {hex(y)}")
        writeFile(c, ext, pe)
        c += 1
        ext = ""
        fileH.seek(0)


def main():
    parser = argparse.ArgumentParser(description="Single-byte XOR decoder and PE detector")
    parser.add_argument("file", help="xored_data")
    args = parser.parse_args()
    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
    key, _ = get_xor()
    if key is None:
        return
    data = xor_data(key)
    carve(data)


if __name__ == "__main__":
    main()
