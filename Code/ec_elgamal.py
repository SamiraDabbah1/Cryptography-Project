from hashlib import sha256
from random import randint
from math import gcd
from random import randrange
from sympy import randprime
import random  # Ensure to import the random module

""" Module for generating ElGamal Digital Signature Scheme systems, keys,
    Signing documents, and verifying signatures.
"""

"""function to check if n prime"""
def is_prime(n, k=30):
    if n <= 3:
        return n == 2 or n == 3
    neg_one = n - 1

    # write n-1 as 2^s*d where d is odd
    s, d = 0, neg_one
    while not d & 1:
        s, d = s+1, d>>1
    assert 2 ** s * d == neg_one and d & 1

    for i in range(k):
        a = randrange(2, neg_one)
        x = pow(a, d, n)
        if x in (1, neg_one):
            continue
        for r in range(1, s):
            x = x ** 2 % n
            if x == 1:
                return False
            if x == neg_one:
                break
        else:
            return False
    return True

"""function to generate a custom prime"""
def custom_randprime(N=10**8):
    p = 1
    while not is_prime(p):
        p = randrange(N)
    return p

"""function to return the inverse of a mod m"""
def inverse(a, m):
    if m == 1:
        return 0

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist.")
    else:
        return (x % m + m) % m

def generate_system(key_length, hash_function):
    """ Generates an ElGamal system """
    # Generate a prime number p
    p = randprime(2 ** (key_length - 1), 2 ** key_length)
    # Generate a base g
    g = random.randint(2, p - 2)
    return (p, g)

def generate_keys(system):
    """ Generates a public-private key pair for an ElGamal system """
    p, g = system
    private_key = randint(1, p - 2)
    public_key = pow(g, private_key, p)
    return (private_key, public_key)

def sign(system, private_key, message):
    """ Signs a message using the private key of an ElGamal system. """
    if not isinstance(message, bytes):
        message = message.encode()  # Ensure the message is bytes-like

    p, g = system
    h = sha256()
    h.update(message)
    message_hash = int.from_bytes(h.digest(), 'big')
    while True:
        k = randint(1, p - 2)
        try:
            k_inv = inverse(k, p - 1)
            break
        except ValueError:
            continue  # Retry with a new k if the inverse does not exist
    r = pow(g, k, p)
    s = (k_inv * (message_hash - private_key * r)) % (p - 1)
    return (r, s)

def verify(system, public_key, message, signature):
    """ Verifies a signature using the public key of an ElGamal system. """
    if not isinstance(message, bytes):
        message = message.encode()  # Ensure the message is bytes-like

    p, g = system
    r, s = signature
    h = sha256()
    h.update(message)
    message_hash = int.from_bytes(h.digest(), 'big')
    if not (0 < r < p) or not (0 < s < (p - 1)):
        return False
    v1 = pow(g, message_hash, p)
    v2 = (pow(public_key, r, p) * pow(r, s, p)) % p
    return v1 == v2
