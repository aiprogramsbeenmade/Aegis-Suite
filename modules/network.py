import socket
import requests


def get_ip_info():
    """Ottiene informazioni sull'IP pubblico corrente tramite API esterna."""
    try:
        # Usiamo ipapi.co per ottenere dati geolocalizzati
        response = requests.get("https://ipapi.co/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "IP": data.get("ip"),
                "Città": data.get("city"),
                "Regione": data.get("region"),
                "Provider": data.get("org"),
                "VPN/Proxy": "Possibile" if data.get("proxy") else "Non rilevato"
            }
        return "Errore nel recupero dati."
    except Exception as e:
        return f"Errore di connessione: {e}"


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