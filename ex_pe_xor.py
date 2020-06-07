#!/usr/bin/env python2
## detects single byte xor encoding by searching for the
## encoded MZ, lfanew and PE, then XORs the data and
## uses pefile to extract the decoded executable.
## written quickly/poorly by alexander hanel

import sys
import struct
import pefile
import re
from StringIO import StringIO

def get_xor():
    # read file into a bytearray
    byte = bytearray(open(sys.argv[1], 'rb').read())

    # for each byte in the file stream, excluding the last 256 bytes
    for i in range(0, len(byte) - 256):
            # KEY ^ VALUE ^ KEY = VALUE; Simple way to get the key
            key = byte[i] ^ ord('M')
            # verify the two bytes contain 'M' & 'Z'
            if chr(byte[i] ^ key) == 'M' and  chr(byte[i+1] ^ key) == 'Z':
                    # skip non-XOR encoded MZ
                    if key == 0:
                            continue
                    # read four bytes into temp, offset to PE aka lfanew
                    temp = byte[(i + 0x3c) : (i + 0x3c + 4)]
                    # decode values with key
                    lfanew = []
                    for x in temp:
                            lfanew.append( x ^ key)
                    # convert from bytearray to int value, probably a better way to do this
                    pe_offset  = struct.unpack( '<i', str(bytearray(lfanew)))[0]
                     # verify results are not negative or read is bigger than file
                    if pe_offset < 0 or pe_offset > len(byte):
                            continue
                    # verify the two decoded bytes are 'P' & 'E'
                    if byte[pe_offset + i ] ^ key == ord('P') and byte[pe_offset + 1 + i] ^ key == ord('E'):
                            print " * Encoded PE Found, Key 0x%x, Offset 0x%x" % (key, i)
                            return (key, i)
    return (None, None)

def getExt(pe):
        if pe.is_dll() == True:
            return 'dll'
        if pe.is_driver() == True:
            return 'sys'
        if pe.is_exe() == True:
            return 'exe'
        else:
            return 'bin'

def writeFile(count, ext, pe):
        try:
            out  = open(str(count)+ '.' + ext, 'wb')
        except:
            print '\t[FILE ERROR] could not write file'
            sys.exit()
        # remove overlay or junk in the trunk
        out.write(pe.trim())
        out.close()

def xor_data(key, offset):
        byte = bytearray(open(sys.argv[1], 'rb').read())
        temp = ''
        for x in byte:
            temp += chr(x ^ key)
        return temp

def carve(fileH):
        if type(fileH) is str:
            fileH = StringIO(fileH)
        c = 1
        # For each address that contains MZ
        for y in [tmp.start() for tmp in re.finditer('\x4d\x5a', fileH.read())]:
            fileH.seek(y)
            try:
                pe = pefile.PE(data=fileH.read())
            except:
                continue
            # determine file ext
            ext = getExt(pe)
            print ' *', ext , 'found at offset', hex(y) 
            writeFile(c,ext,pe)
            c += 1
            ext = ''
            fileH.seek(0)
            pe.close

def run():
    if len(sys.argv) < 2:
        print "Usage: ex_pe_xor.py <xored_data>"
        return
    key, offset = get_xor()
    if key == None:
        return
    data = xor_data(key, offset)
    carve(data)

run()
