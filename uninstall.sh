#!/bin/bash

echo "🗑️  Rimozione Aegis Suite in corso..."

# 1. Trova il file di configurazione della shell
SHELL_RC="$HOME/.zshrc"
if [ ! -f "$SHELL_RC" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

# 2. Rimuovi l'alias dal file di configurazione
if grep -q "alias aegis=" "$SHELL_RC"; then
    # Crea una copia di backup per sicurezza
    cp "$SHELL_RC" "${SHELL_RC}.bak"
    # Rimuove la riga dell'alias
    sed -i '' '/alias aegis=/d' "$SHELL_RC"
    echo "✅ Alias 'aegis' rimosso da $SHELL_RC"
else
    echo "ℹ️ Nessun alias trovato."
fi

# 3. Rimuovi l'ambiente virtuale e i file temporanei
if [ -d "venv" ]; then
    rm -rf venv
    echo "✅ Ambiente virtuale rimosso."
fi

if [ -d "__pycache__" ]; then
    find . -type d -name "__pycache__" -exec rm -rf {} +
    echo "✅ Cache Python pulita."
fi

# 4. Domanda finale: cancellare anche i dati sensibili?
echo -n "⚠️  Vuoi eliminare anche i Vault e i file criptati? (s/n): "
read scelta
if [ "$scelta" == "s" ]; then
    rm -f *.db *.bin *.key .env
    echo "🔥 Tutti i dati sensibili sono stati eliminati."
else
    echo "📁 Vault e chiavi conservati nella cartella attuale."
fi

echo -e "\n✨ Disinstallazione completata. Riavvia il terminale per rendere effettive le modifiche."