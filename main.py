import os
from colorama import Fore, Style, init
from modules import identity, integrity, crypto, network

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
            path = input("Trascina qui il file: ").strip('"')
            print(f"{GREEN}Hash SHA-256: {RESET}{integrity.calculate_sha256(path)}")
        elif scelta == "2":
            path = input("Percorso immagine originale: ").strip('"')
            output = input("Nome file pulito (es. pulita.jpg): ").strip('"')
            print(f"{GREEN}{integrity.scrub_exif(path, output)}")
        elif scelta == "3":
            path = input(f"{RED}Percorso file da distruggere: {RESET}").strip('"')
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
        print(f"{RED}0.{RESET} Esci")

        scelta = input(f"\n{YELLOW}Seleziona un modulo: ")

        if scelta == "1":
            menu_identity()
        elif scelta == "2":
            menu_integrity()
        elif scelta == "3":
            menu_crypto()  # Qui avevi un errore logico (avevi messo lo shredder!)
        elif scelta == "4":
            menu_network()
        elif scelta == "0":
            print(f"{GREEN}Chiusura Aegis Suite. Resta al sicuro!")
            break
        else:
            print(f"{RED}Scelta errata.")
            input("Premi Invio per continuare...")


if __name__ == "__main__":
    main()