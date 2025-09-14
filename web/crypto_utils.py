import random
import json
from sympy import isprime, mod_inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os


# Use secure RSA implementation instead of custom weak crypto
def generate_keys():
    """Generate secure RSA key pair using proper cryptographic library"""
    key = RSA.generate(2048)  # Use proper 2048-bit RSA
    public_key = key.publickey()
    
    # Return keys in a format compatible with existing code
    # but using secure implementation
    return {
        'public': public_key.export_key(),
        'private': key.export_key()
    }, {
        'public': public_key.export_key(), 
        'private': key.export_key()
    }


# Secure encrypt function using PKCS1_OAEP
def encrypt(plaintext, public_key_data):
    """Encrypt plaintext using secure RSA-OAEP"""
    if isinstance(public_key_data, dict):
        public_key = RSA.import_key(public_key_data['public'])
    else:
        public_key = RSA.import_key(public_key_data)
    
    cipher = PKCS1_OAEP.new(public_key)
    
    # For long messages, encrypt in chunks
    max_chunk_size = public_key.size_in_bytes() - 42  # OAEP padding overhead
    plaintext_bytes = plaintext.encode('utf-8')
    
    encrypted_chunks = []
    for i in range(0, len(plaintext_bytes), max_chunk_size):
        chunk = plaintext_bytes[i:i + max_chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
    
    return encrypted_chunks


# Secure decrypt function using PKCS1_OAEP  
def decrypt(ciphertext, private_key_data):
    """Decrypt ciphertext using secure RSA-OAEP"""
    if isinstance(private_key_data, dict):
        private_key = RSA.import_key(private_key_data['private'])
    else:
        private_key = RSA.import_key(private_key_data)
    
    cipher = PKCS1_OAEP.new(private_key)
    
    # Handle both list and string input for backward compatibility
    if isinstance(ciphertext, str):
        try:
            ciphertext = json.loads(ciphertext)
        except json.JSONDecodeError:
            # Single encrypted chunk
            ciphertext = [ciphertext]
    
    decrypted_chunks = []
    for chunk in ciphertext:
        encrypted_data = base64.b64decode(chunk.encode('utf-8'))
        decrypted_chunk = cipher.decrypt(encrypted_data)
        decrypted_chunks.append(decrypted_chunk)
    
    return b''.join(decrypted_chunks).decode('utf-8')


# Secure encryption oracle
def encryption_oracle(plaintext, public_key):
    """Secure encryption oracle using proper RSA"""
    return encrypt(plaintext, public_key)


# Legacy functions for backward compatibility with old weak crypto
# These should be deprecated but kept for migration
def generate_prime_pair():
    """DEPRECATED: Use generate_keys() instead"""
    # Keep for backward compatibility but log warning
    import logging
    logging.warning("generate_prime_pair() is deprecated and insecure. Use generate_keys() instead.")
    while True:
        p = random.randint(100_000, 200_000)
        q = random.randint(100_000, 200_000)
        if isprime(p) and isprime(q) and p != q:
            return p, q


def legacy_generate_keys():
    """DEPRECATED: Legacy key generation - DO NOT USE"""
    import logging
    logging.warning("legacy_generate_keys() is deprecated and insecure. Use generate_keys() instead.")
    p, q = generate_prime_pair()
    n = p * q  # Modulus
    phi_n = (p - 1) * (q - 1)  # Euler's totient function

    # Public key exponent 'e' should be coprime with phi_n
    e = 65537  # A common choice for e

    # Private key exponent 'd' is the modular inverse of e mod phi_n
    d = mod_inverse(e, phi_n)

    return (e, n), (d, n)
