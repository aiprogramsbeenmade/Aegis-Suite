import os
import platform
import subprocess


def check_hardening():
    os_name = platform.system()
    score = 100
    report = []

    print(f"\n🔍 Analisi Hardening per sistema: {os_name}...")

    # 1. Controllo FIREWALL
    if os_name == "Windows":
        try:
            out = subprocess.check_output('netsh advfirewall show allprofiles state', shell=True).decode()
            if "ON" in out:
                report.append(f"✅ Firewall: Attivo")
            else:
                report.append(f"❌ Firewall: DISATTIVATO")
                score -= 30
        except:
            report.append("⚠️ Impossibile verificare Firewall")

    elif os_name == "Darwin":  # macOS
        out = subprocess.check_output(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate']).decode()
        if "enabled" in out:
            report.append(f"✅ Firewall: Attivo")
        else:
            report.append(f"❌ Firewall: DISATTIVATO")
            score -= 30

    # 2. Controllo PRIVILEGI (Root/Admin)
    is_admin = False
    if os_name == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.getuid() == 0

    if is_admin:
        report.append("⚠️ Esecuzione come ADMIN: Rischio elevato in caso di exploit")
        score -= 10
    else:
        report.append("✅ Privilegi: Utente standard (Sicuro)")

    # 3. Controllo FILE SENSIBILI (Solo Unix)
    if os_name in ["Darwin", "Linux"]:
        if os.path.exists("/etc/ssh/sshd_config"):
            report.append("✅ SSH configurato")
        else:
            report.append("ℹ️ SSH non presente (Minore superficie d'attacco)")

    # Calcolo finale del giudizio
    rating = "ECCELLENTE" if score > 85 else ("BUONO" if score > 60 else "VULNERABILE")

    return {
        "score": score,
        "rating": rating,
        "details": report
    }