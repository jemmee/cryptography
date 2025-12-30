# docker run -d --security-opt seccomp=unconfined --cap-add=NET_ADMIN --rm -p 5696:5696 --name kmip altmannmarcelo/kmip:latest

from kmip.pie import client
from kmip.pie import objects
from kmip import enums
import binascii
import os
from kmip.core import enums

# Connect to local Docker KMIP server (no auth/TLS for demo)
c = client.ProxyKmipClient(hostname='localhost', port=5696, ca='/tmp/certs/root_certificate.pem', cert='/tmp/certs/client_certificate_jane_doe.pem', key='/tmp/certs/client_key_jane_doe.pem')

with c:
    # 2. Create a Symmetric Key
    # We define the algorithm (AES), length (128), and what it's allowed to do
    key_id = c.create(
        enums.CryptographicAlgorithm.AES,
        128,
        cryptographic_usage_mask=[
            enums.CryptographicUsageMask.ENCRYPT,
            enums.CryptographicUsageMask.DECRYPT
        ]
    )
    
    # Activate the key so the server allows its use
    c.activate(key_id)
    print(f"Created and Activated Key ID: {key_id}")

    # 3. Encryption
    message = b""
    
    # We specify the key ID, algorithm, and cipher mode
    cipher_text, iv = c.encrypt(
        message,
        uid=key_id,
        cryptographic_parameters={
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
            'block_cipher_mode': enums.BlockCipherMode.CBC,
            'padding_method': enums.PaddingMethod.ANSI_X923
        }
    )
    print(f"Cipher Text: {cipher_text.hex()}")

    # 4. Decryption
    # You must provide the same parameters and the IV received during encryption
    decrypted_data = c.decrypt(
        cipher_text,
        uid=key_id,
        cryptographic_parameters={
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
            'block_cipher_mode': enums.BlockCipherMode.CBC,
            'padding_method': enums.PaddingMethod.ANSI_X923
        },
        iv_counter_nonce=iv
    )

    print(f"Decrypted Result: {decrypted_data.decode('utf-8')}")