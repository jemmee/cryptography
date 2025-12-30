# docker run -d \
#  --name pykmip-server \
#  -p 5696:5696 \
#  altmannmarcelo/kmip:latest
#
# 
# Basic KMIP client demo using PyKMIP – creates key, encrypts/decrypts data

from kmip.pie import client
from kmip.pie import objects
from kmip import enums
import binascii
import os
from kmip.core import enums

# Connect to local Docker KMIP server (no auth/TLS for demo)
with client.ProxyKmipClient(hostname='localhost', port=5696, ca='/tmp/certs/root_certificate.pem', cert='/tmp/certs/client_certificate_jane_doe.pem', key='/tmp/certs/client_key_jane_doe.pem') as kmip_client:
    print("Connected to KMIP server\n")

    # 1. Create a 256-bit symmetric key (AES)
    key_name = "demo-symmetric-key"
    key_id = kmip_client.create(
        enums.ObjectType.SYMMETRIC_KEY,
        objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            256,
            (b'\x00' * 32),  # Dummy bytes – server generates real key
            name=key_name
        ),
        name=key_name
    )
    print(f"Created symmetric key with ID: {key_id}\n")

    # 2. Encrypt some data using the key
    plaintext = b"Hello from KMIP demo!"
    print(f"Plaintext: {plaintext}")

    result = kmip_client.encrypt(
        data=plaintext,
        uid=key_id,
        cryptographic_parameters=objects.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        ),
        iv_nonce=b'\x00' * 16  # Fixed IV for demo (use random in real code)
    )

    ciphertext = result.data
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}\n")

    # 3. Decrypt the ciphertext
    decrypt_result = kmip_client.decrypt(
        data=ciphertext,
        uid=key_id,
        cryptographic_parameters=objects.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        ),
        iv_nonce=b'\x00' * 16
    )

    decrypted = decrypt_result.data
    print(f"Decrypted: {decrypted}")
    print(f"Match: {decrypted == plaintext}")

print("\nKMIP demo complete!")