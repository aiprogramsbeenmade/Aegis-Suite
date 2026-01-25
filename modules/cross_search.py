import webbrowser


def perform_cross_search(username):
    print(f"\n🕵️ Avvio Cross-Search profonda per: {username}")

    # Generiamo URL di ricerca avanzata (Google Dorks)
    queries = {
        "Google (Presenza Totale)": f"https://www.google.com/search?q=\"{username}\"",
        "Pastebin (Possibili Leak)": f"https://www.google.com/search?q=site:pastebin.com+\"{username}\"",
        "Reddit (Discussioni)": f"https://www.google.com/search?q=site:reddit.com+\"{username}\"",
        "HaveIBeenPwned (Data Breaches)": f"https://haveibeenpwned.com/account/{username}"
    }

    found_links = []
    for desc, url in queries.items():
        print(f"🔗 Generazione link per {desc}...")
        found_links.append((desc, url))

    return found_links