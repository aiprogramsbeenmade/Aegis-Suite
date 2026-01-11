import requests
import base64
import os
from dotenv import load_dotenv
import hashlib

# Carica le variabili dal file .env
load_dotenv()

# Recupera la chiave
API_KEY = os.getenv("VT_API_KEY")


def scan_url(url: str):
    """Invia un URL a VirusTotal e restituisce il report di sicurezza."""
    if not API_KEY:
        return "❌ Errore: API Key non trovata nel file .env"

    # Codifica l'URL per l'API v3 di VirusTotal
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(endpoint, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']

            return {
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "total": sum(stats.values())
            }
        elif response.status_code == 404:
            return "🔍 URL mai scansionato. Prova a caricarlo su virustotal.com"
        elif response.status_code == 401:
            return "❌ Errore: API Key non valida o non autorizzata."
        else:
            return f"❌ Errore API: {response.status_code}"

    except Exception as e:
        return f"❌ Errore di connessione: {e}"


def scan_file_hash(file_path: str):
    """Calcola l'hash di un file e verifica se è presente nel database VirusTotal."""
    if not API_KEY:
        return "❌ Errore: API Key non trovata nel file .env"

    try:
        # 1. Calcolo dell'hash SHA-256 del file locale
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # 2. Interrogazione VirusTotal via Hash
        headers = {"accept": "application/json", "x-apikey": API_KEY}
        endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"

        response = requests.get(endpoint, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "hash": file_hash,
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "total": sum(stats.values())
            }
        elif response.status_code == 404:
            return f"🔍 File (Hash: {file_hash[:10]}...) mai visto da VirusTotal. Probabilmente sicuro o molto raro."
        else:
            return f"❌ Errore API: {response.status_code}"

    except FileNotFoundError:
        return "❌ Errore: File non trovato."
    except Exception as e:
        return f"❌ Errore: {e}"