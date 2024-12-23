import base64
import hashlib
import json
import os

from Crypto.Cipher import AES


class AESManager:
    def __init__(self,
                 key_name: str,
                 password: str):
        self.__key_name = key_name
        self.__master_password = hashlib.sha256(f"{key_name}{password}".encode()).digest()

    def __generate_aes_key(self):
        try:
            aes_key: bytes = self.__load_key()
        except FileNotFoundError:
            aes_key: bytes = hashlib.sha256(self.__master_password).digest()
            self.__save_key(aes_key=aes_key)
        return aes_key

    def encrypt(self, plain_bytes: bytes) -> str:
        aes_key = self.__generate_aes_key()  # Генерируем ключ
        try:
            cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(plain_bytes)
            return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
        finally:
            del aes_key  # Удаляем ключ из памяти

    def decrypt(self, encrypted_data: bytes) -> str:
        aes_key = self.__generate_aes_key()  # Генерируем ключ
        try:
            encrypted_data = base64.b64decode(encrypted_data)
            nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
        finally:
            del aes_key  # Удаляем ключ из памяти

    def __encrypt_key(self, key: bytes) -> str:
        """Шифрует ключ перед сохранением."""
        cipher = AES.new(self.__master_password, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(key)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def __decrypt_key(self, encrypted_key: str) -> bytes:
        """Дешифрует ключ при загрузке и проверяет его корректность."""
        encrypted_data = base64.b64decode(encrypted_key)
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        try:
            cipher = AES.new(self.__master_password, AES.MODE_EAX, nonce=nonce)
            decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_key
        except ValueError:
            raise ValueError("Неверный пароль: невозможно расшифровать ключ.")

    def __save_key(self, aes_key: bytes):
        encrypted_key = self.__encrypt_key(aes_key)
        file_path = "aes_keys.json"

        # Проверяем существование файла и загружаем данные
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                try:
                    data = json.load(file)
                except json.JSONDecodeError:
                    data = {}
        else:
            data = {}

        # Обновляем данные
        data[self.__key_name] = encrypted_key

        # Сохраняем обратно в файл
        with open(file_path, "w") as file:
            json.dump(data, file, indent=4)

    def __load_key(self) -> bytes:
        file_path = "aes_keys.json"

        # Проверяем наличие файла
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл {file_path} не найден.")

        # Загружаем данные
        with open(file_path, "r") as file:
            data = json.load(file)
            if self.__key_name in data:
                encrypted_key: str = data[self.__key_name]
                return self.__decrypt_key(encrypted_key)
            else:
                raise FileNotFoundError("Ключ с указанным именем не найден.")
