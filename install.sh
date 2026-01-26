#!/bin/bash

echo "🛡️ Inizializzazione Aegis Suite Config..."

# 1. Creazione ambiente virtuale
python3 -m venv venv
source venv/bin/activate

# 2. Installazione dipendenze e pacchetto
pip install --upgrade pip
pip install -e .
pip3 install -r requirements.txt

# 3. Creazione Alias nel sistema (opzionale se non usi setup.py)
SHELL_RC="$HOME/.zshrc"
if [ ! -f "$SHELL_RC" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if ! grep -q "alias aegis=" "$SHELL_RC"; then
    echo "alias aegis='cd $(pwd) && source venv/bin/activate && python3 main.py'" >> "$SHELL_RC"
    echo "✅ Comando 'aegis' aggiunto a $SHELL_RC"
else
    echo "ℹ️ Il comando 'aegis' esiste già."
fi

echo "🚀 Installazione completata! Riavvia il terminale o digita 'source $SHELL_RC' e scrivi 'aegis'."