#!/usr/bin/python3
import sys
import struct

def extract_payload(zip_file, output_file):
    
    with open(zip_file, 'rb') as f:
        data = f.read()
    
    marker = b'\x55\x55\x55\x55'
    pos = data.find(marker)
    
    if pos == -1:
        print("Marker not found")
        return False
    
    start = pos + 4
    
    eocd_sig = b'\x50\x4b\x05\x06'
    eocd_pos = data.find(eocd_sig, start)
    
    if eocd_pos == -1:
        print("EOCD not found")
        return False
    
    payload = data[start:eocd_pos]
    
    with open(output_file, 'wb') as f:
        f.write(payload)
    
    print(f"[+] Extracted {len(payload)} bytes to {output_file}")
    return True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 extract.py <zip_file> <output_file>")
        sys.exit(1)
    
    extract_payload(sys.argv[1], sys.argv[2])