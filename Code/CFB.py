import os

# Import FEAL functions (assumed to be defined earlier)
from feal_4 import encrypt as feal_encrypt, decrypt as feal_decrypt, key_generation

def cfb_encrypt(key, iv, plaintext, segment_size):
    # Ensure segment size is a multiple of 8 bits
    if segment_size % 8 != 0:
        raise ValueError("Segment size must be a multiple of 8 bits")
    
    segment_size_bytes = segment_size // 8

    # Ensure segment size is valid
    if segment_size_bytes < 1 or segment_size_bytes > 8:  # FEAL block size is 8 bytes
        raise ValueError("Invalid segment size")

    ciphertext = b''
    current_iv = iv

    # Generate subkeys for FEAL
    subkey = key_generation(key)

    # Process each plaintext segment
    for i in range(0, len(plaintext), segment_size_bytes):
        segment = plaintext[i:i + segment_size_bytes]
        
        # Compute O(j) = CIPH(I(j))
        o = feal_encrypt(current_iv, subkey)
        
        # Compute C(j) = P(j) XOR MSB(O(j))
        c_segment = bytes([segment[j] ^ o[j] for j in range(len(segment))])
        ciphertext += c_segment

        # Compute I(j+1) = LSB(I(j)) | C(j)
        current_iv = current_iv[segment_size_bytes:] + c_segment

    return ciphertext

def cfb_decrypt(key, iv, ciphertext, segment_size):
    # Ensure segment size is a multiple of 8 bits
    if segment_size % 8 != 0:
        raise ValueError("Segment size must be a multiple of 8 bits")
    
    segment_size_bytes = segment_size // 8

    # Ensure segment size is valid
    if segment_size_bytes < 1 or segment_size_bytes > 8:  # FEAL block size is 8 bytes
        raise ValueError("Invalid segment size")

    plaintext = b''
    current_iv = iv

    # Generate subkeys for FEAL
    subkey = key_generation(key)

    # Process each ciphertext segment
    for i in range(0, len(ciphertext), segment_size_bytes):
        segment = ciphertext[i:i + segment_size_bytes]
        
        # Compute O(j) = CIPH(I(j))
        o = feal_encrypt(current_iv, subkey)
        
        # Compute P(j) = C(j) XOR MSB(O(j))
        p_segment = bytes([segment[j] ^ o[j] for j in range(len(segment))])
        plaintext += p_segment

        # Compute I(j+1) = LSB(I(j)) | C(j)
        current_iv = current_iv[segment_size_bytes:] + segment

    return plaintext
