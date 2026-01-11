import os
from colorama import Fore, Style, init
from modules import identity, integrity, crypto, network, web_scan, steganography

# Inizializza colorama
init(autoreset=True)

# --- DEFINIZIONE COSTANTI COLORE ---
# Usiamo nomi chiari che richiamano il colore stesso per evitare confusione
CYAN = Fore.CYAN + Style.BRIGHT
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
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
        elif scelta == "0":
            print(f"{GREEN}Chiusura Aegis Suite. Resta al sicuro!")
            break
        else:
            print(f"{RED}Scelta errata.")
            input("Premi Invio per continuare...")




if __name__ == "__main__":
    main()