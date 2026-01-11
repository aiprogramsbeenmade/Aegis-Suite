import os
from modules import identity, integrity, crypto, network


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def menu_identity():
    while True:
        print("\n--- AEGIS SUITE: Identity Protection ---")
        print("1. Analizza Password (Forza & Leak)")
        print("2. Genera Passphrase")
        print("3. Genera Password Casuale")
        print("0. Torna al menu principale")

        scelta = input("\nScegli un'opzione: ")

        if scelta == "1":
            pwd = input("Inserisci la password da testare: ")
            print(f"\nAnalisi: {identity.check_strength(pwd)}")
            print(f"Status Leak: {identity.check_pwd_pwned(pwd)}")
        elif scelta == "2":
            n = int(input("Quante parole? (default 4): ") or 4)
            print(f"\nPassphrase Generata: {identity.generate_passphrase(num_words=n)}")
        elif scelta == "3":
            lunghezza = int(input("Lunghezza? (default 16): ") or 16)
            print(f"\nPassword Generata: {identity.generate_random_password(length=lunghezza)}")
        elif scelta == "0":
            break
        else:
            print("Opzione non valida.")


def menu_integrity():
    while True:
        print("\n--- AEGIS SUITE: Sicurezza File ---")
        print("1. Calcola Hash SHA-256 (Integrità)")
        print("2. EXIF Metadata Scrubber (Privacy Foto)")
        print("3. Secure Shredder (Eliminazione Definitiva)")
        print("0. Torna al menu principale")

        scelta = input("\nScegli un'opzione: ")

        if scelta == "1":
            path = input("Trascina qui il file o inserisci il percorso: ").strip('"')
            print(f"Hash SHA-256: {integrity.calculate_sha256(path)}")

        elif scelta == "2":
            path = input("Percorso immagine originale: ").strip('"')
            output = input("Nome/Percorso del file pulito (es. pulita.jpg): ").strip('"')
            print(integrity.scrub_exif(path, output))

        elif scelta == "3":
            path = input("ATTENZIONE: Percorso file da distruggere: ").strip('"')
            conferma = input(f"Sei sicuro di voler eliminare {path}? (s/n): ")
            if conferma.lower() == 's':
                print(integrity.secure_delete(path))
            else:
                print("Operazione annullata.")

        elif scelta == "0":
            break


def menu_crypto():
    while True:
        print("\n--- AEGIS SUITE: Privacy Sandbox (AES-256) ---")
        print("1. Cripta un messaggio")
        print("2. Decripta un messaggio")
        print("0. Torna al menu principale")

        scelta = input("\nScegli un'opzione: ")

        if scelta == "1":
            msg = input("Inserisci il messaggio segreto: ")
            pwd = input("Imposta una password di cifratura: ")
            encrypted = crypto.encrypt_text(msg, pwd)
            print(f"\nMessaggio Criptato:\n{encrypted}")

        elif scelta == "2":
            enc_msg = input("Incolla qui il messaggio criptato: ")
            pwd = input("Inserisci la password per decifrare: ")
            decrypted = crypto.decrypt_text(enc_msg, pwd)
            print(f"\nRisultato: {decrypted}")

        elif scelta == "0":
            break


def menu_network():
    while True:
        print("\n--- AEGIS SUITE: Diagnostica Rete ---")
        print("1. Verifica IP Pubblico (VPN Test)")
        print("2. Scansione Porte Locale (Port Scanner)")
        print("0. Torna al menu principale")

        scelta = input("\nScegli un'opzione: ")

        if scelta == "1":
            info = network.get_ip_info()
            if isinstance(info, dict):
                for k, v in info.items():
                    print(f"{k}: {v}")
            else:
                print(info)

        elif scelta == "2":
            target = input("Inserisci IP da scansionare (default 127.0.0.1): ") or "127.0.0.1"
            print("Inizio scansione (porte 1-1024)...")
            open_ports = network.port_scanner(target)
            if open_ports:
                print(f"⚠️ Porte aperte trovate: {open_ports}")
            else:
                print("✅ Nessuna porta aperta rilevata nel range standard.")

        elif scelta == "0":
            break


def main():
    while True:
        clear_screen()
        print("======================================")
        print("          AEGIS SUITE v1.0            ")
        print("======================================")
        print("1. Identity Protection")
        print("2. Sicurezza File")
        print("3. Crittografia")
        print("4. Diagnostica Rete")
        print("0. Esci")

        scelta = input("\nSeleziona un modulo: ")

        if scelta == "1":
            menu_identity()
        elif scelta == "2":
            menu_integrity()
        elif scelta == "3":
            menu_crypto()
        elif scelta == "4":
            menu_network()
        elif scelta == "0":
            print("Chiusura Aegis Suite. Resta al sicuro!")
            break
        else:
            print("Modulo non ancora implementato o scelta errata.")
            input("Premi Invio per continuare...")


if __name__ == "__main__":
    main()