import math
import secrets
import string
import hashlib
import requests


def calculate_entropy(password):
    """Calcola l'entropia della password in bit."""
    if not password:
        return 0

    charset_size = 0
    if any(c in string.ascii_lowercase for c in password): charset_size += 26
    if any(c in string.ascii_uppercase for c in password): charset_size += 26
    if any(c in string.digits for c in password): charset_size += 10
    if any(c in string.punctuation for c in password): charset_size += 32

    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
    return round(entropy, 2)


def check_strength(password):
    """Valuta la qualità della password basandosi sull'entropia."""
    entropy = calculate_entropy(password)
    if entropy < 40:
        return f"Debole ({entropy} bit) - Vulnerabile a brute-force rapido."
    elif entropy < 60:
        return f"Media ({entropy} bit) - Accettabile per account secondari."
    elif entropy < 80:
        return f"Forte ({entropy} bit) - Molto sicura."
    else:
        return f"Eccellente ({entropy} bit) - Standard militare."


def generate_passphrase(num_words=4, separator="-"):
    """Genera una passphrase usando una lista di parole (mockup semplificato)."""
    # In un caso reale, caricheresti un file .txt con migliaia di parole (es. lista EFF)
    word_list = ["sicurezza", "cripto", "scudo", "rete", "onda", "fuoco", "ombra", "chiave", "zenit", "radar"]
    selected_words = [secrets.choice(word_list) for _ in range(num_words)]
    return separator.join(selected_words)


def generate_random_password(length=16):
    """Genera una password casuale ad alta entropia."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def check_pwd_pwned(password):
    """Verifica se la password è apparsa in data breach (API HIBP)."""
    # Creiamo l'hash SHA-1 della password
    sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return "Errore di connessione al servizio HIBP."

        # La risposta contiene una lista di suffissi e il numero di volte che sono stati visti
        hashes = (line.split(':') for line in response.text.splitlines())

        for h, count in hashes:
            if h == suffix:
                return f"⚠️ PERICOLO: Questa password è apparsa in {count} leak!"

        return "✅ Sicura: Questa password non è stata trovata nei database pubblici dei breach."

    except requests.exceptions.RequestException:
        return "Errore: Impossibile contattare il server di verifica."

# Nota: Per il leak checker delle EMAIL, HIBP richiede una API KEY a pagamento.
# Per ora implementiamo solo quello delle PASSWORD che è gratuito e anonimo.