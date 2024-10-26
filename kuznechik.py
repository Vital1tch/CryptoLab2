from gost3412 import GOST3412Kuznechik
from gost3413 import ecb_decrypt
from binascii import unhexlify
import os

# Входные данные
file_name = "28-enc.png"
key_hex = "92cbc979bde9a873df4cad2d63659ba19358af07d23085e5b1643f6503ff0fc9"

# Пути к директориям
encrypted_dir = "encrypted"  # Директория с зашифрованными файлами
decrypted_dir = "decrypted"  # Директория для сохранения расшифрованных файлов

# Ключ должен быть преобразован в байты
key = unhexlify(key_hex)

# Путь к зашифрованному файлу
encrypted_file_path = os.path.join(encrypted_dir, file_name)

# Открытие зашифрованного файла
try:
    with open(encrypted_file_path, "rb") as enc_file:
        enc_data = enc_file.read()
except FileNotFoundError:
    print(f"Ошибка: Файл {encrypted_file_path} не найден.")
    exit(1)

# Используем ГОСТ Магма с режимом ECB для расшифровки
gost_decipher = GOST3412Kuznechik(key)

# Расшифровываем данные
plain_data = ecb_decrypt(gost_decipher.decrypt, gost_decipher.blocksize, enc_data)

# Создаем директорию decrypted, если она не существует
os.makedirs(decrypted_dir, exist_ok=True)

# Путь к расшифрованному файлу
decrypted_file_name = file_name.replace(".png", "-decrypted.png")
decrypted_file_path = os.path.join(decrypted_dir, decrypted_file_name)

# Сохранение расшифрованного файла
try:
    with open(decrypted_file_path, "wb") as dec_file:
        dec_file.write(plain_data)
    print(f"Файл успешно расшифрован и сохранен как {decrypted_file_path}")
except IOError as e:
    print(f"Ошибка при сохранении файла: {e}")
    exit(1)



