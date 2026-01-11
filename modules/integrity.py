import hashlib
import os
from PIL import Image


def calculate_sha256(file_path):
    """Calcola l'hash SHA-256 di un file per verificarne l'integrità."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Leggiamo a blocchi per non saturare la RAM con file grandi
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "Errore: File non trovato."


def scrub_exif(image_path, output_path):
    """Rimuove i metadati EXIF (GPS, data, modello camera) da un'immagine."""
    try:
        img = Image.open(image_path)
        # Creiamo una nuova immagine senza i dati EXIF
        data = list(img.getdata())
        img_no_exif = Image.new(img.mode, img.size)
        img_no_exif.putdata(data)
        img_no_exif.save(output_path)
        return f"✅ Immagine pulita salvata in: {output_path}"
    except Exception as e:
        return f"Errore durante la pulizia: {e}"


def secure_delete(file_path, passes=3):
    """Sovrascrive il file con dati casuali prima di eliminarlo (Shredding)."""
    try:
        if not os.path.isfile(file_path):
            return "Errore: Il percorso non è un file valido."

        file_size = os.path.getsize(file_path)
        with open(file_path, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                # Sovrascrive con byte casuali crittograficamente sicuri
                f.write(os.urandom(file_size))

        os.remove(file_path)
        return "✅ File eliminato definitivamente e sovrascritto."
    except Exception as e:
        return f"Errore durante l'eliminazione sicura: {e}"