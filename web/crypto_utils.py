import random
import json
from sympy import isprime, mod_inverse


# Generate two distinct prime numbers p and q
def generate_prime_pair():
    while True:
        p = random.randint(100_000, 200_000)
        q = random.randint(100_000, 200_000)
        if isprime(p) and isprime(q) and p != q:
            return p, q


# Calculate the RSA public and private keys
def generate_keys():
    p, q = generate_prime_pair()
    n = p * q  # Modulus
    phi_n = (p - 1) * (q - 1)  # Euler's totient function

    # Public key exponent 'e' should be coprime with phi_n
    e = 65537  # A common choice for e

    # Private key exponent 'd' is the modular inverse of e mod phi_n
    d = mod_inverse(e, phi_n)

    return (e, n), (d, n)


# Encrypt a plaintext with the public key
def encrypt(plaintext, public_key):
    e, n = public_key
    return [pow(ord(char), e, n) for char in plaintext]


# Decrypt a ciphertext with the private key
def decrypt(ciphertext, private_key):
    d, n = private_key
    # Ensure ciphertext is a list of integers
    if isinstance(ciphertext, str):
        ciphertext = json.loads(ciphertext)
    return "".join([chr(pow(char, d, n)) for char in ciphertext])


# Insecure oracle: gives the ciphertext of the plaintext without revealing the key
def encryption_oracle(plaintext, public_key):
    return encrypt(plaintext, public_key)
