import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


# --- FUNZIONI DI SUPPORTO ---

def get_key_from_password(password, salt):
    """Genera una chiave a 256-bit usando PBKDF2 (compatibile con tutto il file)."""
    return PBKDF2(password, salt, dkLen=32, count=100000)


# --- CRITTOGRAFIA TESTO (Per Messaggi e Note) ---

def encrypt_text(text: str, password: str):
    """Cripta testo usando pycryptodome."""
    salt = get_random_bytes(16)
    key = get_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    padded_data = pad(text.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    combined = salt + iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')


def decrypt_text(combined_base64: str, password: str):
    """Decripta testo usando pycryptodome."""
    try:
        data = base64.b64decode(combined_base64)
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]

        key = get_key_from_password(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception:
        return "❌ Errore: Password errata o messaggio corrotto."


# --- GESTIONE NOTE ---

def save_secure_note(filename, content, password):
    encrypted = encrypt_text(content, password)
    if not os.path.exists("vault"):
        os.makedirs("vault")
    with open(f"vault/{filename}.aegis", "w") as f:
        f.write(encrypted)
    return f"Nota '{filename}' salvata in /vault."


def load_secure_note(filename, password):
    try:
        with open(f"vault/{filename}.aegis", "r") as f:
            encrypted_content = f.read()
        return decrypt_text(encrypted_content, password)
    except FileNotFoundError:
        return "❌ Errore: Nota non trovata."


# --- CRITTOGRAFIA FILE (Binary Chunking) ---

def encrypt_file(file_path, password):
    CHUNK_SIZE = 64 * 1024
    salt = get_random_bytes(16)
    key = get_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    base_path = os.path.splitext(file_path)[0]
    output_path = f"{base_path}.aegis"

    try:
        with open(file_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(salt)
            f_out.write(iv)
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if len(chunk) == 0: break
                if len(chunk) % 16 != 0:
                    chunk = pad(chunk, 16)
                f_out.write(cipher.encrypt(chunk))
        return f"✅ File criptato: {output_path}"
    except Exception as e:
        return f"❌ Errore: {e}"


def decrypt_file(file_path, password, original_extension=".txt"):
    CHUNK_SIZE = 64 * 1024
    try:
        with open(file_path, "rb") as f_in:
            salt = f_in.read(16)
            iv = f_in.read(16)
            key = get_key_from_password(password, salt)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            output_path = file_path.replace(".aegis", original_extension)
            with open(output_path, "wb") as f_out:
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if len(chunk) == 0: break
                    decrypted_chunk = cipher.decrypt(chunk)
                    if len(f_in.peek(1)) == 0:
                        decrypted_chunk = unpad(decrypted_chunk, 16)
                    f_out.write(decrypted_chunk)
        return f"✅ File decriptato: {output_path}"
    except Exception:
        return "❌ Password errata o file corrotto."