import socket
import requests

import requests


def get_ip_info():
    # Lista di servizi diversi per evitare il blocco 429
    services = [
        "http://ip-api.com/json/",
        "https://ipapi.co/json/",
        "https://api.ipify.org?format=json"
    ]

    for url in services:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                # Normalizziamo i dati perché ogni servizio usa nomi diversi
                return {
                    "IP": data.get("query") or data.get("ip"),
                    "Paese": data.get("country_name") or data.get("country"),
                    "Città": data.get("city"),
                    "ISP": data.get("isp") or data.get("org") or "N/D"
                }
            elif response.status_code == 429:
                continue  # Salta al prossimo servizio se questo è limitato
        except Exception:
            continue  # Prova il prossimo se c'è un errore di connessione

    return "❌ Errore: Tutti i servizi di IP Intelligence sono temporaneamente indisponibili."

def port_scanner(target_ip, port_range=(1, 1024)):
    """Scansiona un range di porte su un IP specifico."""
    open_ports = []
    print(f"Scansione in corso su {target_ip}...")

    for port in range(port_range[0], port_range[1] + 1):
        # Creiamo un socket per tentare la connessione
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)  # Timeout molto breve per velocità

        result = s.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()

    return open_ports