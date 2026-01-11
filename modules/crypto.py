import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def _derive_key(password: str, salt: bytes):
    """Deriva una chiave a 256-bit da una password usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_text(text: str, password: str):
    """Cripta un testo usando AES-256 e restituisce una stringa in Base64."""
    salt = os.urandom(16)
    iv = os.urandom(16)  # Initialization Vector
    key = _derive_key(password, salt)

    # Padding del testo per renderlo multiplo di 128 bit (blocco AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Uniamo Salt + IV + Messaggio per poter decriptare in seguito
    combined = salt + iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')


def decrypt_text(combined_base64: str, password: str):
    """Decripta un messaggio criptato con Aegis Suite."""
    try:
        data = base64.b64decode(combined_base64)
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]

        key = _derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Rimozione del padding
        unpadder = padding.PKCS7(128).unpadder()
        original_text = unpadder.update(padded_data) + unpadder.finalize()

        return original_text.decode('utf-8')
    except Exception:
        return "❌ Errore: Password errata o messaggio corrotto."