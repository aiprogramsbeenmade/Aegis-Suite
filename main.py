import os
from colorama import Fore, Style, init
from modules import identity, integrity, crypto, network, web_scan, steganography, password_manager, persona, social_finder, hardening, emoji_crypto, cross_search
import webbrowser
# Inizializza colorama
init(autoreset=True)

# --- DEFINIZIONE COSTANTI COLORE ---
# Usiamo nomi chiari che richiamano il colore stesso per evitare confusione
CYAN = Fore.CYAN + Style.BRIGHT
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
WHITE = Fore.WHITE
RESET = Style.RESET_ALL

# Alias per logica (opzionali, ma utili)
HEADER = CYAN
INFO = GREEN
WARN = YELLOW
ALERT = RED

def clean_path(path):
    """Pulisce il percorso del file da spazi extra, virgolette e backslash."""
    if not path:
        return ""
    # Rimuove virgolette e spazi bianchi all'inizio/fine (incluso quello del drag-and-drop)
    path = path.strip().replace("'", "").replace('"', "")
    # Sistema i backslash degli spazi tipici del terminale Mac/Linux
    path = path.replace("\\ ", " ")
    return path


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def menu_identity():
    while True:
        print(f"\n{CYAN}--- 🆔 AEGIS SUITE: Identity Protection ---")
        print(f"{GREEN}1.{RESET} Analizza Password (Forza & Leak)")
        print(f"{GREEN}2.{RESET} Genera Passphrase")
        print(f"{GREEN}3.{RESET} Genera Password Casuale")
        print(f"{RED}0.{RESET} Torna al menu principale")

        scelta = input(f"\n{YELLOW}Scegli un'opzione: ")

        if scelta == "1":
            pwd = input("Inserisci la password da testare: ")
            strength = identity.check_strength(pwd)
            leak = identity.check_pwd_pwned(pwd)

            # Colorazione dinamica dei risultati
            s_col = RED if "Debole" in strength else GREEN
            l_col = RED if "PERICOLO" in leak else GREEN

            print(f"\nAnalisi: {s_col}{strength}")
            print(f"Status Leak: {l_col}{leak}")
        elif scelta == "2":
            n = int(input("Quante parole? (default 4): ") or 4)
            print(f"\n{GREEN}Passphrase Generata: {RESET}{identity.generate_passphrase(num_words=n)}")
        elif scelta == "3":
            lunghezza = int(input("Lunghezza? (default 16): ") or 16)
            print(f"\n{GREEN}Password Generata: {RESET}{identity.generate_random_password(length=lunghezza)}")
        elif scelta == "0":
            break


def menu_integrity():
    while True:
        print(f"\n{CYAN}--- 📂 AEGIS SUITE: Sicurezza File ---")
        print(f"{GREEN}1.{RESET} Calcola Hash SHA-256 (Integrità)")
        print(f"{GREEN}2.{RESET} EXIF Metadata Scrubber (Privacy Foto)")
        print(f"{GREEN}3.{RESET} Secure Shredder (Eliminazione Definitiva)")
        print(f"{RED}0.{RESET} Torna al menu principale")

        scelta = input(f"\n{YELLOW}Scegli un'opzione: ")

        if scelta == "1":
            path = clean_path(input("Trascina qui il file: ").strip('"'))
            print(f"{GREEN}Hash SHA-256: {RESET}{integrity.calculate_sha256(path)}")
        elif scelta == "2":
            path = clean_path(input("Percorso immagine originale: ").strip('"'))
            output = input("Nome file pulito (es. pulita.jpg): ").strip('"')
            print(f"{GREEN}{integrity.scrub_exif(path, output)}")
        elif scelta == "3":
            path = clean_path(input(f"{RED}Percorso file da distruggere: {RESET}").strip('"'))
            print(f"{RED}!!! ATTENZIONE: AZIONE IRREVERSIBILE !!!")
            conferma = input(f"{YELLOW}Sei sicuro? (s/n): ")
            if conferma.lower() == 's':
                print(f"{GREEN}{integrity.secure_delete(path)}")
        elif scelta == "0":
            break


def menu_crypto():
    while True:
        print(f"\n{CYAN}--- 🔐 AEGIS SUITE: Privacy Sandbox ---")
        print(f"{GREEN}1.{RESET} Cripta un messaggio")
        print(f"{GREEN}2.{RESET} Decripta un messaggio")
        print(f"{RED}0.{RESET} Torna al menu principale")

        scelta = input(f"\n{YELLOW}Scegli un'opzione: ")

        if scelta == "1":
            msg = input("Messaggio segreto: ")
            pwd = input("Password di cifratura: ")
            encrypted = crypto.encrypt_text(msg, pwd)
            print(f"\n{GREEN}Messaggio Criptato:\n{RESET}{encrypted}")
        elif scelta == "2":
            enc_msg = input("Incolla messaggio criptato: ")
            pwd = input("Inserisci password: ")
            decrypted = crypto.decrypt_text(enc_msg, pwd)
            print(f"\n{GREEN}Risultato: {RESET}{decrypted}")
        elif scelta == "0":
            break


def menu_network():
    while True:
        print(f"\n{CYAN}--- 🌐 AEGIS SUITE: Network Health ---")
        print(f"{GREEN}1.{RESET} Verifica IP Pubblico")
        print(f"{GREEN}2.{RESET} Port Scanner Locale")
        print(f"{RED}0.{RESET} Torna al menu")

        scelta = input(f"\n{YELLOW}Scegli: ")

        if scelta == "1":
            info = network.get_ip_info()
            print(f"\n{CYAN}Dati rilevati:")
            if isinstance(info, dict):
                for k, v in info.items():
                    print(f"{GREEN}{k}:{RESET} {v}")
            else:
                print(f"{RED}{info}")
        elif scelta == "2":
            target = input("IP Target (default 127.0.0.1): ") or "127.0.0.1"
            ports = network.port_scanner(target)
            if ports:
                print(f"{RED}⚠️ PORTE APERTE: {ports}")
            else:
                print(f"{GREEN}✅ Nessuna porta critica aperta.")
        elif scelta == "0":
            break


def menu_web_scan():
    while True:
        print(f"\n{CYAN}--- 🛡️  AEGIS SUITE: URL Scanner (VirusTotal) ---")
        print(f"{GREEN}1.{RESET} Scansiona un URL")
        print(f"{GREEN}2.{RESET} Scansiona un File")
        print(f"{RED}0.{RESET} Torna al menu principale")

        scelta = input(f"\n{YELLOW}Scegli un'opzione: ")

        if scelta == "1":
            target_url = input(f"\nInserisci l'URL da controllare: ").strip()
            if not target_url.startswith("http"):
                print(f"{WARN}Nota: Assicurati di includere http:// o https://")

            print(f"{CYAN}Interrogazione database VirusTotal in corso...")
            results = web_scan.scan_url(target_url)

            if isinstance(results, dict):
                print(f"\n{HEADER}REPORT DI ANALISI:")
                print(f"--------------------------")

                # Colori dinamici in base alla pericolosità
                m_color = RED if results['malicious'] > 0 else GREEN
                s_color = YELLOW if results['suspicious'] > 0 else RESET

                print(f"{m_color}Maligni:   {results['malicious']}")
                print(f"{s_color}Sospetti:  {results['suspicious']}")
                print(f"{GREEN}Innocui:   {results['harmless']}")
                print(f"{RESET}Analisi totali effettuate: {results['total']}")
                print(f"--------------------------")

                # Logica di valutazione intelligente
                if results['malicious'] > 3:  # Soglia di allerta impostata a 3
                    print(f"{RED}⚠️  PERICOLO: Questo link è segnalato come maligno da più fonti!")
                elif results['malicious'] > 0:
                    print(
                        f"{YELLOW}ℹ️  NOTA: Rilevato un possibile falso positivo ({results['malicious']} segnalazione).")
                    print(f"{GREEN}✅ Il link è probabilmente sicuro (99%).")
                elif results['suspicious'] > 0:
                    print(f"{YELLOW}⚠️  ATTENZIONE: Alcuni motori hanno dubbi su questo link.")
                else:
                    print(f"{GREEN}✅ PULITO: Nessuna minaccia rilevata.")
            else:
                # Mostra l'errore se non è un dizionario (es. API Key mancante)
                print(results)

        elif scelta == "2":
            path = clean_path(input(f"\nTrascina il file da analizzare: ").strip('"').strip())
            print(f"{CYAN}Calcolo hash e ricerca nel database...")
            results = web_scan.scan_file_hash(path)

            if isinstance(results, dict):
                print(f"\n{HEADER}RISULTATO ANALISI FILE:")
                print(f"Hash SHA-256: {results['hash']}")

                m_color = RED if results['malicious'] > 3 else (YELLOW if results['malicious'] > 0 else GREEN)
                print(f"{m_color}Segnalazioni Maligne: {results['malicious']}")

                if results['malicious'] > 3:
                    print(f"{RED}⚠️  ALLERTA: File pericoloso rilevato!")
                elif results['malicious'] > 0:
                    print(f"{YELLOW}ℹ️  Possibile falso positivo, procedi con cautela.")
                else:
                    print(f"{GREEN}✅ Nessuna minaccia nota per questo file.")
            else:
                print(results)

        elif scelta == "0":
            break


def menu_privacy_secrets():
    while True:
        print(f"\n{CYAN}--- 🤐 AEGIS SUITE: Privacy & Secrets ---")
        print(f"{GREEN}1.{RESET} Crea Nota Protetta (.aegis)")
        print(f"{GREEN}2.{RESET} Leggi Nota Protetta")
        print(f"{GREEN}3.{RESET} Nascondi testo in Immagine (Steganografia)")
        print(f"{GREEN}4.{RESET} Estrai testo da Immagine")
        print(f"{RED}0.{RESET} Torna al menu principale")

        scelta = input(f"\n{YELLOW}Scegli: ")

        if scelta == "1":
            name = input("Nome nota: ")
            content = input("Scrivi il contenuto segreto: ")
            pwd = input("Imposta Password: ")
            print(crypto.save_secure_note(name, content, pwd))

        elif scelta == "2":
            name = input("Nome nota da aprire: ")
            pwd = input("Inserisci Password: ")
            print(f"\n{CYAN}Contenuto: {RESET}{crypto.load_secure_note(name, pwd)}")

        elif scelta == "3":
            img = clean_path(input("Percorso immagine (PNG consigliata): ").strip('"'))
            msg = input("Messaggio segreto: ")
            out = input("Nome file output (es. segreto.png): ")
            print(steganography.encode_image(img, msg, out))

        elif scelta == "4":
            img = clean_path(input("Percorso immagine con segreto: ").strip('"'))
            print(f"\n{CYAN}Messaggio trovato: {RESET}{steganography.decode_image(img)}")

        elif scelta == "0":
            break


def menu_crypto_files():
    while True:
        print(f"\n{CYAN}--- 🔒 AEGIS SUITE: File Locker ---")
        print(f"{GREEN}1.{RESET} Cripta un File (supporto universale)")
        print(f"{GREEN}2.{RESET} Decripta un File (.aegis)")
        print(f"{RED}0.{RESET} Torna indietro")

        scelta = input(f"\n{YELLOW}Scegli un'opzione: ")

        if scelta == "1":
            path = clean_path(input("Trascina qui il file da criptare: ").strip('"').strip())
            pwd = input("Imposta una password di cifratura: ")

            # Cripta il file
            risultato = crypto.encrypt_file(path, pwd)
            print(risultato)

            # Opzione extra: Shredding del file originale
            if "successo" in risultato:
                choice = input(f"{WARN}Vuoi eliminare definitivamente il file originale in chiaro? (s/n): ")
                if choice.lower() == 's':
                    integrity.secure_delete(path)
                    print(f"{GREEN}File originale rimosso in modo sicuro.")


        elif scelta == "2":

            path = clean_path(input(f"\n{YELLOW}Trascina il file .aegis: {RESET}").strip('"').strip())

            if not path.endswith(".aegis"):
                print(f"{RED}❌ Errore: Seleziona un file con estensione .aegis!{RESET}")

                continue

            pwd = input(f"{YELLOW}Inserisci la password: {RESET}")

            print(f"\n{CYAN}--- Ripristino Estensione ---{RESET}")

            print("Che tipo di file era in origine?")

            print("1. Testo (.txt)")

            print("2. Immagine (.jpg / .png)")

            print("3. Documento (.pdf)")

            print("4. Altro (inserisci estensione manualmente)")

            ext_choice = input(f"\n{YELLOW}Scegli opzione: {RESET}")

            if ext_choice == "1":
                ext = ".txt"

            elif ext_choice == "2":
                ext = input("Specifica (jpg o png): ").strip(); ext = f".{ext}"

            elif ext_choice == "3":
                ext = ".pdf"

            else:
                ext = input("Inserisci estensione (es. .zip, .docx): ").strip()

            if not ext.startswith("."): ext = "." + ext

            # Chiamata alla funzione di decriptazione con la ciliegina

            print(f"\n{CYAN}Decriptazione in corso...{RESET}")

            print(crypto.decrypt_file(path, pwd, original_extension=ext))

        elif scelta == "0":
            break


def menu_pass_manager():
    from modules import password_manager, password_manager  # Importiamo anche il nuovo modulo persona
    master_pwd = input(f"\n{YELLOW}Inserisci la tua Master Password per accedere: {RESET}")

    vault = password_manager.load_vault(master_pwd)
    if vault is None:
        print(f"{RED}❌ Accesso negato: Master Password errata.{RESET}")
        return

    while True:
        print(f"\n{CYAN}--- 🛡️  AEGIS VAULT: Passwords & Documents ---")
        print(f"{GREEN}1.{RESET} Visualizza tutto il contenuto")
        print(f"{GREEN}2.{RESET} Cerca una voce")
        print(f"{GREEN}3.{RESET} Aggiungi nuova Password")
        print(f"{GREEN}4.{RESET} Aggiungi Documento (ID, Patente, etc.)")
        print(f"{CYAN}5.{RESET} Generatore Identità Fake")
        print(f"{RED}6.{RESET} Elimina una voce")
        print(f"{RED}0.{RESET} Torna al menu principale")

        scelta = input(f"\n{YELLOW}Scegli: ")

        if scelta == "1":
            if not vault:
                print("Il vault è vuoto.")
            else:
                for srv, data in vault.items():
                    # Gestiamo la visualizzazione in base al tipo di dato
                    tipo = data.get('tipo', 'Password').upper()
                    print(f"[{tipo}] {CYAN}{srv.capitalize()}{RESET}")
                    for k, v in data.items():
                        if k != 'tipo': print(f"  └ {k}: {v}")

        elif scelta == "2":
            srv = input("Nome servizio o documento da cercare: ").lower()
            if srv in vault:
                print(f"\n{GREEN}Trovato!{RESET} Dati: {vault[srv]}")
            else:
                print(f"{RED}Nessun dato trovato per: {srv}{RESET}")

        elif scelta == "3":
            srv = input("Servizio: ")
            usr = input("Username: ")
            print(f"\n{CYAN}--- Suggerimento Sicurezza ---{RESET}")
            pwd = input(f"{YELLOW}Password (lascia vuoto per generarla): {RESET}")

            if not pwd:
                from modules import identity
                pwd = identity.generate_random_password(16)
                print(f"{GREEN}Generata: {RESET}{pwd}")
            else:
                from modules import identity
                val = identity.check_strength(pwd)
                col = RED if "Debole" in val else (YELLOW if "Media" in val else GREEN)
                print(f"Sicurezza: {col}{val}{RESET}")
                if "Debole" in val and input("Usare comunque? (s/n): ").lower() != 's': continue

            # Aggiungiamo il tipo 'Password' per distinguerlo dai documenti
            vault[srv.lower()] = {"tipo": "Password", "user": usr, "pw": pwd}
            password_manager.save_vault(vault, master_pwd)
            print(f"{GREEN}✅ Salvata!{RESET}")

        elif scelta == "4":
            # --- NUOVA FUNZIONE DOCUMENTI ---
            tipo_doc = input("Tipo documento (es. Patente, Carta Identità): ")
            num = input("Numero documento: ")
            scadenza = input("Data di scadenza: ")
            vault[tipo_doc.lower()] = {"tipo": "Documento", "numero": num, "scadenza": scadenza}
            password_manager.save_vault(vault, master_pwd)
            print(f"{GREEN}✅ Documento salvato!{RESET}")

        elif scelta == "5":
            # --- NUOVA FUNZIONE IDENTITY FAKE ---
            fake = persona.generate_fake_identity()
            print(f"\n{YELLOW}--- IDENTITÀ FAKE GENERATA ---{RESET}")
            for k, v in fake.items(): print(f"{k}: {v}")

            if input(f"\nVuoi salvare questa identità nel Vault? (s/n): ").lower() == 's':
                tag = input("Etichetta (es. Account Estero): ")
                fake['tipo'] = "FakeID"
                vault[tag.lower()] = fake
                password_manager.save_vault(vault, master_pwd)
                print(f"{GREEN}✅ Salvata nel Vault.{RESET}")

        elif scelta == "6":
            srv = input("Nome della voce da eliminare: ").lower()
            if srv in vault:
                if input(f"{RED}Confermi eliminazione di {srv}? (s/n): {RESET}").lower() == 's':
                    del vault[srv]
                    password_manager.save_vault(vault, master_pwd)
                    print(f"{GREEN}Eliminata.{RESET}")
            else:
                print(f"{RED}Voce non trovata.{RESET}")

        elif scelta == "0":
            break


def menu_social_finder():
    from modules import social_finder

    print(f"\n{CYAN}--- 🕵️ AEGIS OSINT: Social Media Finder ---{RESET}")
    target = input("Inserisci l'username da cercare: ")

    if not target:
        print("Username non valido.")
        return

    risultati = social_finder.check_socials(target)

    print(f"\n{YELLOW}Risultati per '{target}':{RESET}")
    print("-" * 40)

    for social, info in risultati.items():
        if info["status"] == "Trovato":
            print(f"{GREEN}[✔] {social}: {info['url']}{RESET}")
        elif info["status"] == "Errore connessione":
            print(f"{YELLOW}[!] {social}: Timeout o Errore{RESET}")
        else:
            print(f"{RED}[✘] {social}: Non trovato{RESET}")

    print("-" * 40)
    input(f"\nPremi Invio per tornare al menu...")


def menu_hardening():
    from modules import hardening

    print(f"\n{CYAN}--- 🛡️  AEGIS: System Hardening Check ---{RESET}")
    input("Premi Invio per avviare la scansione del sistema...")

    risultati = hardening.check_hardening()

    print(f"\n{YELLOW}RISULTATO ANALISI:{RESET}")
    for item in risultati["details"]:
        print(f" {item}")

    colore_score = GREEN if risultati["score"] > 80 else (YELLOW if risultati["score"] > 50 else RED)
    print(f"\n{WHITE}Punteggio Sicurezza: {colore_score}{risultati['score']}/100{RESET}")
    print(f"Giudizio: {colore_score}{risultati['rating']}{RESET}")

    if risultati["score"] < 100:
        print(f"\n{CYAN}Suggerimento: {RESET}Attiva il firewall o usa un utente non-admin per navigare.")

    input(f"\nPremi Invio per tornare al menu...")


def menu_osint_crypto():
    print(f"\n{CYAN}--- 🎭 AEGIS: Special Ops Module ---{RESET}")
    print(f"{GREEN}1.{RESET} Text-to-Emoji (Cripta)")
    print(f"{GREEN}2.{RESET} Emoji-to-Text (Decripta)")
    print(f"{GREEN}3.{RESET} Username Cross-Search (Deep OSINT)")
    print(f"{RED}0.{RESET} Indietro")

    scelta = input(f"\n{YELLOW}Scegli: ")

    if scelta == "1":
        msg = input("Inserisci il messaggio segreto: ")
        pwd = input("Imposta una password di sblocco: ")
        from modules import emoji_crypto
        risultato = emoji_crypto.encrypt_to_emoji(msg, pwd)
        print(f"\n{CYAN}Messaggio camuffato:{RESET}\n{risultato}")

    elif scelta == "2":
        emsg = input("Incolla le emoji da decriptare: ")
        pwd = input("Inserisci la password: ")
        from modules import emoji_crypto
        print(f"\n{GREEN}Messaggio originale:{RESET} {emoji_crypto.decrypt_from_emoji(emsg, pwd)}")

    elif scelta == "3":
        user = input("Username da investigare: ")
        from modules import cross_search
        links = cross_search.perform_cross_search(user)
        print(f"\n{YELLOW}Analisi completata. Vuoi aprire i link di ricerca nel browser? (s/n){RESET}")
        if input().lower() == 's':
            for desc, url in links:
                webbrowser.open(url)

def main():
    while True:
        clear_screen()
        print(HEADER + "======================================")
        print(HEADER + "          🛡️  AEGIS SUITE v1.0         ")
        print(HEADER + "======================================")
        print(f"{GREEN}1.{RESET} Identity Protection")
        print(f"{GREEN}2.{RESET} Sicurezza File")
        print(f"{GREEN}3.{RESET} Crittografia")
        print(f"{GREEN}4.{RESET} Diagnostica Rete")
        print(f"{GREEN}5.{RESET} URL Scanner (VirusTotal)")
        print(f"{GREEN}6.{RESET} Steganografia/Note Private")
        print(f"{GREEN}7.{RESET} File Locker (Cripta/Decripta File)")
        print(f"{GREEN}8.{RESET} Password Manager (Vault)")
        print(f"{GREEN}9.{RESET} Social Media Finder")
        print(f"{GREEN}10.{RESET} Controllo Sicurezza Computer")
        print(f"{GREEN}11.{RESET} Ulteriori Funzioni")
        print(f"{RED}0.{RESET} Esci")

        scelta = input(f"\n{YELLOW}Seleziona un modulo: ")

        if scelta == "1":
            menu_identity()
        elif scelta == "2":
            menu_integrity()
        elif scelta == "3":
            menu_crypto()
        elif scelta == "4":
            menu_network()
        elif scelta == "5":
            menu_web_scan()
        elif scelta == "6":
            menu_privacy_secrets()
        elif scelta == "7":
            menu_crypto_files()
        elif scelta == "8":
            menu_pass_manager()
        elif scelta == "9":
            menu_social_finder()
        elif scelta == "10":
            menu_hardening()
        elif scelta == "11":
            menu_osint_crypto()
        elif scelta == "0":
            print(f"{GREEN}Chiusura Aegis Suite. Resta al sicuro!")
            break
        else:
            print(f"{RED}Scelta errata.")
            input("Premi Invio per continuare...")




if __name__ == "__main__":
    main()