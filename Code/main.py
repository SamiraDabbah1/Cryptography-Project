import random
from hashlib import sha256
from ec_elgamal import generate_system, generate_keys, sign, verify
from feal_4 import encrypt as feal_encrypt, decrypt as feal_decrypt, key_generation
from merkle_hellman_knapsack import generate_private_key, generate_public_key, encrypt as mh_encrypt, decrypt as mh_decrypt, generate_modulus_multiplier
from CFB import cfb_encrypt, cfb_decrypt

# Function to convert bytes to binary string
def bytes_to_binary_string(byte_data):
    return ''.join(format(byte, '08b') for byte in byte_data)

# Function to safely decode bytes to string
def safe_decode(byte_data):
    try:
        return byte_data.decode('utf-8')
    except UnicodeDecodeError:
        return byte_data.decode('latin1')

# Generating Merkle-Hellman knapsack private key and parameters
mh_private_key = generate_private_key(64)  # Adjusted length to 64 bits
q, r = generate_modulus_multiplier(mh_private_key)
mh_public_key = generate_public_key(mh_private_key, q, r)
print(">>> Bob generates a pair of Merkle-Hellman knapsack keys and shares the public key.")

# Generating ElGamal DS system for Alice
#print(">>> Alice generates ElGamal DS system.")
alice_elgsys = generate_system(128, sha256())
alice_sig_keys = generate_keys(alice_elgsys)
print(">>> Alice shares the public key with Bob.")

# Generating private key (64 bits) and IV (64 bits) for FEAL CFB
print(">>> Alice generates private FEAL-CFB key and IV.")
feal_key = random.getrandbits(64).to_bytes(8, byteorder='big')  # Adjusted to 64 bits
iv = random.getrandbits(64).to_bytes(8, byteorder='big')

# Get the message from the user
message = input("Enter the message to encrypt: ").encode('utf-8')

# Encrypt the message using FEAL in CFB mode
print(">>> Alice encrypts the message using FEAL in CFB mode.")
segment_size = 64  # Segment size in bits
ciphertext = cfb_encrypt(feal_key, iv, message, segment_size)

# Sign the ciphertext using EC EL-GAMAL
print(">>> Alice signs the ciphertext using EC EL-GAMAL.")
signature = sign(alice_elgsys, alice_sig_keys[0], sha256(ciphertext).digest())

# Convert FEAL key to binary string
feal_key_bin = bytes_to_binary_string(feal_key)

# Encrypt the FEAL key using Merkle-Hellman knapsack
if len(feal_key_bin) != len(mh_public_key):
    raise ValueError("The length of the FEAL key in binary must match the length of the Merkle-Hellman public key.")

print(">>> Alice encrypts the FEAL key using Merkle-Hellman knapsack.")
encrypted_feal_key = mh_encrypt(feal_key_bin, mh_public_key)

# Decrypt the FEAL key using Merkle-Hellman knapsack
print(">>> Bob decrypts the FEAL key using Merkle-Hellman knapsack.")
decrypted_feal_key_bin = mh_decrypt(encrypted_feal_key, mh_private_key, q, r)
decrypted_feal_key = int(decrypted_feal_key_bin, 2).to_bytes(8, byteorder='big')

# Decrypt the message using FEAL in CFB mode
print(">>> Bob decrypts the message using FEAL in CFB mode.")
decrypted_message = cfb_decrypt(decrypted_feal_key, iv, ciphertext, segment_size)

# Verify the signature using EC EL-GAMAL
print(">>> Bob verifies the signature using EC EL-GAMAL.")
is_valid_signature = verify(alice_elgsys, alice_sig_keys[1], sha256(ciphertext).digest(), signature)

# Output the results
print(f"Original Message: {message.decode('utf-8')}")
print(f"Decrypted Message: {safe_decode(decrypted_message)}")
print(f"Is the signature valid? {'Yes' if is_valid_signature else 'No'}")
