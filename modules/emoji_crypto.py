import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Mappa semplice per trasformare Base64 in Emoji
# Mappa aggiornata con TUTTI i caratteri del Base64 URL-Safe
EMOJI_MAP = {
    'A': '😀', 'B': '😁', 'C': '😂', 'D': '🤣', 'E': '😃', 'F': '😄', 'G': '😅', 'H': '😆',
    'I': '😉', 'J': '😊', 'K': '😋', 'L': '😎', 'M': '😍', 'N': '😘', 'O': '🥰', 'P': '😗',
    'Q': '😙', 'R': '😚', 'S': '☺️', 'T': '🙂', 'U': '🤗', 'V': '🤩', 'W': '🤔', 'X': '🤨',
    'Y': '😐', 'Z': '😑', 'a': '😶', 'b': '🙄', 'c': '😏', 'd': '😣', 'e': '😥', 'f': '😮',
    'g': '🤐', 'h': '😯', 'i': '😪', 'j': '😫', 'k': '🥱', 'l': '😴', 'm': '😌', 'n': '😛',
    'o': '😜', 'p': '😝', 'q': '🤤', 'r': '😒', 's': '😓', 't': '😔', 'u': '😕', 'v': '🙃',
    'w': '🤑', 'x': '😲', 'y': '🙁', 'z': '😖', '0': '😞', '1': '😟', '2': '😤', '3': '😢',
    '4': '😭', '5': '😦', '6': '😧', '7': '😨', '8': '😩', '9': '🤯',
    '+': '🌟', '/': '🌈', '=': '✨', '-': '🛸', '_': '👽'
}
REVERSE_MAP = {v: k for k, v in EMOJI_MAP.items()}
def get_key(password):
    salt = b'aegis_emoji_salt' # Salt fisso per semplicità di scambio
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_to_emoji(text, password):
    f = Fernet(get_key(password))
    encrypted_b64 = f.encrypt(text.encode()).decode()
    return "".join(EMOJI_MAP.get(char, char) for char in encrypted_b64)

def decrypt_from_emoji(emoji_text, password):
    try:
        b64_text = "".join(REVERSE_MAP.get(char, char) for char in emoji_text)
        f = Fernet(get_key(password))
        return f.decrypt(b64_text.encode()).decode()
    except:
        return "❌ Decriptazione fallita: password errata o emoji corrotte."