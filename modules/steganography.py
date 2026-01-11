from PIL import Image


def encode_image(image_path, secret_data, output_path):
    img = Image.open(image_path)
    # Convertiamo il messaggio in binario
    binary_secret = ''.join(format(ord(i), '08b') for i in secret_data) + '1111111111111110'  # Marker di fine

    data_idx = 0
    pixels = img.load()

    for y in range(img.size[1]):
        for x in range(img.size[0]):
            r, g, b = pixels[x, y]
            # Modifichiamo il bit meno significativo (LSB) del rosso
            if data_idx < len(binary_secret):
                r = (r & ~1) | int(binary_secret[data_idx])
                data_idx += 1
            pixels[x, y] = (r, g, b)
            if data_idx >= len(binary_secret):
                img.save(output_path)
                return "✅ Messaggio nascosto nell'immagine!"
    return "❌ Errore: Immagine troppo piccola per il messaggio."


def decode_image(image_path):
    img = Image.open(image_path)
    binary_data = ""
    pixels = img.load()

    for y in range(img.size[1]):
        for x in range(img.size[0]):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)

            if binary_data.endswith('1111111111111110'):
                binary_data = binary_data[:-16]
                chars = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
                return "".join([chr(int(c, 2)) for c in chars])
    return "❌ Nessun messaggio segreto trovato."