import base64

def rc4_crypt(key, data):
    s = list(range(256))
    j = 0
    
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    
    i = 0
    j = 0
    result = bytearray()
    
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        result.append(byte ^ k)
    
    return bytes(result)


def decode_flag():
    KEY = "5Z507SIXfUZOkVLO"
    FLAG = "7u38PKgtNjFWi+OKqp88igSzDzF/T5FaeOKOAQw1TrwQkie+wfOVF2R/OgmanobEZNP90aIYQA=="
    
    encrypted_data = base64.b64decode(FLAG) 
    key_bytes = KEY.encode('utf-8')
    decrypted_data = rc4_crypt(key_bytes, encrypted_data)
    flag = decrypted_data.decode('utf-8')
    print(flag)
    return flag

if __name__ == "__main__":
    decode_flag()