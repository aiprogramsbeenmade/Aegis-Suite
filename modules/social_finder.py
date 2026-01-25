import requests
import time
import random


def check_socials(username):
    platforms = {
        "Instagram": f"https://www.instagram.com/{username}/",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Steam": f"https://steamcommunity.com/id/{username}"
    }

    # Lista di vari User-Agent per simulare browser diversi
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/119.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
    ]

    results = {}
    print(f"\n🔍 Ricerca 'Stealth' avviata per: {username}")
    print(f"⏳ Nota: i ritardi casuali evitano il ban dai server.\n")

    for name, url in platforms.items():
        # Scegliamo un browser casuale per ogni richiesta
        headers = {"User-Agent": random.choice(user_agents)}

        try:
            # Inviamo la richiesta
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)

            # Alcuni siti (come Instagram) possono rispondere 200 ma mandarti alla login.
            # Un controllo più fine aiuterebbe, ma il 200 è già un ottimo indicatore.
            if response.status_code == 200:
                results[name] = {"status": "Trovato", "url": url}
                print(f"✅ {name}: Trovato!")
            elif response.status_code == 404:
                results[name] = {"status": "Non trovato", "url": None}
                print(f"❌ {name}: Libero")
            elif response.status_code == 429:
                results[name] = {"status": "Rate Limited", "url": None}
                print(f"⚠️ {name}: Troppe richieste (Ban temporaneo)")
            else:
                results[name] = {"status": f"Errore {response.status_code}", "url": None}

        except Exception as e:
            results[name] = {"status": "Errore", "url": None}
            print(f"❓ {name}: Non raggiungibile")

        # --- IL RITARDO CASUALE ---
        # Aspetta tra 1 e 3 secondi prima del prossimo sito
        attesa = random.uniform(1.0, 3.0)
        time.sleep(attesa)

    return results