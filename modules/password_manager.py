import json
import os
from modules import crypto

VAULT_PATH = "vault/passwords.aegis"


def load_vault(master_password):
    """Carica e decripta il vault delle password."""
    if not os.path.exists(VAULT_PATH):
        return {}  # Se non esiste, restituisce un dizionario vuoto

    # Usiamo il sistema di decriptazione testo che abbiamo già
    with open(VAULT_PATH, "r") as f:
        encrypted_data = f.read()

    decrypted_data = crypto.decrypt_text(encrypted_data, master_password)

    if "❌ Errore" in decrypted_data:
        return None  # Password errata

    try:
        return json.loads(decrypted_data)
    except:
        return {}


def save_vault(vault_data, master_password):
    """Cripta e salva il vault su disco."""
    if not os.path.exists("vault"):
        os.makedirs("vault")

    json_string = json.dumps(vault_data)
    encrypted_data = crypto.encrypt_text(json_string, master_password)

    with open(VAULT_PATH, "w") as f:
        f.write(encrypted_data)
    return True


def add_password(service, username, password, master_password):
    vault = load_vault(master_password)
    if vault is None: return "❌ Master Password errata!"

    vault[service.lower()] = {"user": username, "pw": password}
    save_vault(vault, master_password)
    return f"✅ Password per {service} salvata correttamente."


def get_password(service, master_password):
    vault = load_vault(master_password)
    if vault is None: return "❌ Master Password errata!"

    entry = vault.get(service.lower())
    if entry:
        return entry
    return "❌ Servizio non trovato."


def delete_password(service, master_password):
    """Rimuove una credenziale dal vault."""
    vault = load_vault(master_password)
    if vault is None: return "❌ Master Password errata!"

    service_key = service.lower()
    if service_key in vault:
        del vault[service_key]
        save_vault(vault, master_password)
        return f"✅ Credenziali per '{service}' eliminate con successo."
    return "❌ Servizio non trovato nel vault."