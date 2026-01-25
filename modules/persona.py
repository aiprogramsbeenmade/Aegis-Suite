import random
import string


def generate_fake_identity():
    nomi_m = ["Matteo", "Luca", "Davide", "Marco", "Simone", "Valerio"]
    nomi_f = ["Giulia", "Elena", "Chiara", "Martina", "Alice", "Roberta"]
    cognomi = ["Rossi", "Ferrari", "Russo", "Bianchi", "Romano", "Gallo", "Costa"]
    citta = ["Roma", "Milano", "Napoli", "Torino", "Palermo", "Bologna"]
    domini = ["@duck.com", "@proton.me", "@tutanota.com", "@skiff.com"]

    sesso = random.choice(["M", "F"])
    nome = random.choice(nomi_m if sesso == "M" else nomi_f)
    cognome = random.choice(cognomi)

    anno = random.randint(1975, 2005)
    data_nascita = f"{random.randint(1, 28):02d}/{random.randint(1, 12):02d}/{anno}"

    user = f"{nome.lower()}{cognome.lower()}{random.randint(10, 99)}"
    email = f"{user}{random.choice(domini)}"

    # Genera una password sicura al volo per questa identità
    pwd = "".join(random.choices(string.ascii_letters + string.digits, k=14))

    return {
        "Nome Completo": f"{nome} {cognome}",
        "Sesso": sesso,
        "Data di Nascita": data_nascita,
        "Città": random.choice(citta),
        "Email Suggerita": email,
        "Password Suggerita": pwd
    }