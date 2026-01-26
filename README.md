# 🛡️ Aegis Suite v1.1

Aegis Suite è un multitool di cybersecurity modulare scritto in Python. Progettato per la protezione dell'identità, l'analisi dell'integrità dei file, la crittografia sicura e la diagnostica di rete.

## ✨ Caratteristiche Principali

### 🆔 Identity Protection
* **Password Analyzer:** Verifica la robustezza e la presenza in leak pubblici (Pwned).
* **Generator:** Crea passphrase sicure e password casuali ad alta entropia.

### 📂 File Security & Integrity
* **Hash Calculator:** Calcolo SHA-256 per verificare l'integrità.
* **Metadata Scrubber:** Rimuove i dati EXIF dalle immagini per proteggere la privacy.
* **Secure Shredder:** Eliminazione definitiva e irreversibile dei file.

### 🔐 Privacy & Secrets
* **AES-256 Text Encryption:** Cifratura simmetrica per messaggi testuali.
* **Secure Notes:** Crea e leggi note protette salvate localmente in formato `.aegis`.
* **Steganography:** Nascondi messaggi segreti all'interno dei pixel delle immagini (LSB).
* **Aegis Vault:** Password manager avanzato con supporto per documenti (ID, Patente) e identità fake "usa e getta".
* **System Hardening Check:** Audit istantaneo della sicurezza del OS (Firewall, privilegi e configurazioni critiche).

### 🌐 Network & Intelligence
* **Network Health:** Info IP pubblico e Port Scanner locale.
* **VirusTotal Scanner:** Analisi in tempo reale di URL e Hash di file sospetti tramite API globale.

### 🎭 Special Ops & OSINT
* **Social Media Finder:** Localizza username su oltre 50 piattaforme con tecniche anti-rilevamento.
* **Username Cross-Search:** Analisi profonda tramite Google Dorks per individuare tracce digitali.
* **Text-to-Emoji Encryption:** Cripta messaggi in stringhe di emoji (Stealth Mode), ideale per comunicazioni discrete.

---

## 🚀 Installazione Manuale

1. **Clona il repository:**
   ```bash
   git clone https://github.com/aiprogramsbeenmade/Aegis-Suite.git
   cd Aegis-Suite
   
2. **Crea un ambiente virtuale (consigliato):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Su macOS/Linux
   # Oppure su Windows: venv\bin\Scripts\activate
   
3. **Installa le dipendenze:**
   ```bash
   pip install -r requirements.txt
   
4. **Configurazione API VirusTotal:**
   Per abilitare lo scanner di URL e File, crea un file `.env` nella cartella principale del progetto e inserisci la tua chiave personale:
   ```text
   VT_API_KEY=la_tua_chiave_personale_qui
   
5. **Avvia Aegis Suite:**
   ```bash
   python3 main.py
---
## 🚀 Installazione Automatica

1. **Scarica l'ultima release:** Clicca [QUI](https://github.com/aiprogramsbeenmade/Aegis-Suite/releases)
2. **Decomprimi il file**
3. **Esegui lo script di installazione:**
   ```bash
   chmod +x install.sh uninstall.sh
   ./install.sh
4. **Configurazione API VirusTotal:**
   Per abilitare lo scanner di URL e File, crea un file `.env` nella cartella principale del progetto e inserisci la tua chiave personale:
   ```text
   VT_API_KEY=la_tua_chiave_personale_qui
   
5. **Riavvia il terminale e digita:**
   ```bash
   aegis
## 🛠️ Tecnologie Utilizzate
* **Python 3.12+**
* **Colorama:** Per un'interfaccia CLI moderna e colorata.
* **PyCryptodome:** Crittografia di grado militare (AES-256).
* **Pillow:** Per la manipolazione dei pixel (Steganografia LSB).
* **Requests:** Per l'integrazione con l'intelligence di VirusTotal.
* **Dotenv:** Per la gestione sicura delle credenziali e chiavi API.

## 🤝 Contribuisci
Le pull request sono benvenute! Per modifiche importanti, apri prima un'issue per discutere cosa vorresti cambiare.

## ⚖️ Licenza
Distribuito sotto licenza **MIT**. Consulta il file `LICENSE` per maggiori dettagli.

---

> **⚠️ DISCLAIMER:** Aegis Suite è stato creato esclusivamente a scopo didattico e per la sicurezza personale. L'autore non si assume alcuna responsabilità per l'uso improprio o illegale di questo software. Utilizzalo responsabilmente.
