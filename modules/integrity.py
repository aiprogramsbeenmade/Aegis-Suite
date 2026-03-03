import hashlib
import os
from PIL import Image, ExifTags
from pillow_heif import register_heif_opener

# Registra il supporto per i file .HEIC dell'iPhone
register_heif_opener()

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "Errore: File non trovato."

def get_exif_data(image_path):
    """Estrae i metadati EXIF, con gestione robusta per HEIC (iPhone)."""
    try:
        img = Image.open(image_path)
        
        # Usiamo getexif() che è il metodo più moderno e compatibile
        exif_raw = img.getexif()
        
        if not exif_raw:
            return "Nessun metadato EXIF trovato."

        exif_info = {}
        # Estraiamo i tag base (Modello, Data, etc.)
        for tag, value in exif_raw.items():
            decoded = ExifTags.TAGS.get(tag, tag)
            exif_info[decoded] = value

        # --- GESTIONE GPS SPECIFICA PER IPHONE/HEIC ---
        # Il tag 0x8825 corrisponde alle informazioni GPS
        gps_info = exif_raw.get_ifd(0x8825) 
        
        if gps_info:
            gps_data = {}
            for t in gps_info:
                sub_tag = ExifTags.GPSTAGS.get(t, t)
                gps_data[sub_tag] = gps_info[t]
            
            # Funzione interna robusta per la conversione
            def to_decimal(coords, ref):
                # Se coords è un singolo valore (errore di lettura), lo gestiamo
                if not hasattr(coords, '__iter__'):
                    return None
                
                # Calcolo gradi decimali: Gradi + Minuti/60 + Secondi/3600
                try:
                    d = float(coords[0])
                    m = float(coords[1])
                    s = float(coords[2])
                    decimal = d + (m / 60.0) + (s / 3600.0)
                    if ref in ['S', 'W']: decimal = -decimal
                    return decimal
                except:
                    return None

            if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                lat = to_decimal(gps_data['GPSLatitude'], gps_data.get('GPSLatitudeRef', 'N'))
                lon = to_decimal(gps_data['GPSLongitude'], gps_data.get('GPSLongitudeRef', 'E'))
                
                if lat is not None and lon is not None:
                    exif_info['GoogleMapsLink'] = f"https://www.google.com/maps?q={lat},{lon}"

        return exif_info
    except Exception as e:
        return f"Errore durante la lettura: {str(e)}"

def scrub_exif(image_path, output_path):
    try:
        img = Image.open(image_path)
        data = list(img.getdata())
        img_no_exif = Image.new(img.mode, img.size)
        img_no_exif.putdata(data)
        
        # Se è HEIC, salviamo forzatamente in JPG
        if image_path.lower().endswith(".heic"):
            if not output_path.lower().endswith(".jpg"):
                output_path += ".jpg"
            img_no_exif.save(output_path, "JPEG")
        else:
            img_no_exif.save(output_path)
            
        return f"✅ Immagine pulita salvata in: {output_path}"
    except Exception as e:
        return f"Errore durante la pulizia: {e}"

def secure_delete(file_path, passes=3):
    try:
        if not os.path.isfile(file_path): return "Errore: File non trovato."
        file_size = os.path.getsize(file_path)
        with open(file_path, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
        os.remove(file_path)
        return f"🗑️ File eliminato definitivamente."
    except Exception as e:
        return f"Errore: {e}"
