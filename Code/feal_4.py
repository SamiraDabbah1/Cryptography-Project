from utils import *

def key_generation(key, rounds=4):
    # https://link.springer.com/content/pdf/10.1007/3-540-38424-3_46.pdf
    # """
    # Generate subkeys for the FEAL-4 encryption algorithm.
    
    # Args:
    #     key (list): The initial key, split into left (Kl) and right (Kr) parts.
    #     rounds (int): The number of rounds for the encryption process.
        
    # Returns:
    #     list: A list of subkeys generated for the encryption process.
    # """
    subkeys = [0] * (rounds//2 + 4)
    Kl, Kr = key[:8], [0] * 8
    Kr1, Kr2 = Kr[:4], Kr[4:]
    Qr = xor(Kr1, Kr2)
    A0, B0 = Kl[:4], Kl[4:]
    D0 = [0] * 4

    for i in range(rounds//2 + 4):
        if i % 3 == 1:
            xored = xor(B0, Kr1)
        elif i % 3 == 0:
            xored = xor(B0, Qr)
        else:
            xored = xor(B0, Kr2)

        xored = xor(xored, D0) if i > 0 else xored
        D0 = A0[0:4]
        b = A0
        A0 = Fk(A0, xored)
        subkeys[4 * i: 4 * i + 2] = A0[0:2]
        subkeys[4 * i + 2: 4 * i + 4] = A0[2:4]
        A0, B0 = B0, A0

    return subkeys

def pad(data):
    #"""
    # Pad the data to be a multiple of 8 bytes.
    
    # Args:
    #     data (bytes): The data to be padded.
        
    # Returns:
    #     bytes: The padded data.
    # """
    return data + bytes([0x00 for _ in range((8 - len(data)) % 8)])

def split(L_R):
    # """
    # Split the data into left and right parts.
    
    # Args:
    #     L_R (bytes): The data to be split.
        
    # Returns:
    #     tuple: A tuple containing the left and right parts of the data.
    # """
    return (L_R[:4], L_R[4:])

def encrypt(data, subkey, N=4):
    # """
    # Encrypt the data using FEAL-4 encryption algorithm.
    
    # Args:
    #     data (bytes): The data to be encrypted.
    #     subkey (list): The subkeys generated for encryption.
    #     N (int): The number of rounds for the encryption process.
        
    # Returns:
    #     bytes: The encrypted data.
    # """
    result = []
    data = pad(data)

    for k in range(len(data) // 8):
        bloc = data[k * 8:(k + 1) * 8]
        L, R = split(bloc)
        L = xor(L, subkey[-2 * 4:-4])
        R = xor(R, subkey[-4:])
        R = xor(L, R)

        for i in range(N):
            L = xor(L, F1(xor(R, subkey[i * 4:(i + 1) * 4])))
            L, R = R, L

        L, R = R, L
        R = xor(R, L)
        result += L + R

    return bytes(result)

def decrypt(data, subkey, N=4):
    #"""
    # Decrypt the data using FEAL-4 encryption algorithm.
    
    # Args:
    #     data (bytes): The data to be decrypted.
    #     subkey (list): The subkeys generated for decryption.
    #     N (int): The number of rounds for the decryption process.
        
    # Returns:
    #     bytes: The decrypted data.
    # """
    result = []
    
    for k in range(len(data) // 8):
        bloc = data[k * 8:(k + 1) * 8]
        L, R = split(bloc)
        R = xor(L, R)
        L, R = R, L
        
        for i in reversed(range(N)):
            L, R = R, L
            L = xor(L, F1(xor(subkey[i * 4:(i + 1) * 4], R)))

        R = xor(R, L)
        R = xor(R, subkey[-4:])
        L = xor(L, subkey[-2 * 4:-4])
        result += L + R

    return bytes(result).strip(b'\x00')

