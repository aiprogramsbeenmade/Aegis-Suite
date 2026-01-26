import requests
import subprocess

CURRENT_VERSION = "2.0"
REPO_URL = "https://api.github.com/repos/aiprogramsbeenmade/Aegis-Suite/tags/latest"


def check_for_updates():
    try:
        response = requests.get(REPO_URL, timeout=3)
        if response.status_code == 200:
            latest_release = response.json()
            latest_version = latest_release['tag_name'].replace('v', '')

            if latest_version > CURRENT_VERSION:
                print(
                    f"\n{chr(27)}[93m🚀 Nuova versione disponibile: v{latest_version} (Attuale: v{CURRENT_VERSION}){chr(27)}[0m")
                print(f"Changelog: {latest_release['name']}")
                choice = input("Vuoi aggiornare ora? (s/n): ")
                if choice.lower() == 's':
                    update_project()
    except Exception:
        # Silenzioso se non c'è internet o errori API
        pass


def update_project():
    print("⏳ Scaricamento aggiornamenti tramite Git...")
    try:
        subprocess.run(["git", "pull", "origin", "main"], check=True)
        print("✅ Aggiornamento completato! Riavvia Aegis per applicare le modifiche.")
        exit()
    except Exception as e:
        print(f"❌ Errore durante l'aggiornamento: {e}")