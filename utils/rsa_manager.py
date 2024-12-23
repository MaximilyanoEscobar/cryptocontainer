import base64
import json
import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from .aes_manager import AESManager


class RSAManager:
    def __init__(self, key_name: str, password: str):
        self.__key_name = key_name
        self.__aes_manager = AESManager(key_name=key_name, password=password)
        self.__generate_key_pair()
        self.__public_key = self.__load_public_key()

    def public_key(self):
        return self.__public_key

    def __generate_key_pair(self):
        """Создает новую пару RSA-ключей и сохраняет приватный ключ в зашифрованном виде."""
        key = RSA.generate(2048)
        private_key = key.export_key()

        # Сохраняем приватный ключ, зашифровав его AESManager
        self.__save_private_key(private_key)

    def encrypt(self, plain_bytes: bytes) -> str:
        """Шифрует сообщение с использованием публичного ключа."""
        # public_key = self.__load_public_key()
        cipher = PKCS1_OAEP.new(self.__public_key)
        ciphertext = cipher.encrypt(plain_bytes)
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, encrypted_data: bytes) -> str:
        """Дешифрует сообщение с использованием приватного ключа."""
        private_key = self.__load_private_key()
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = base64.b64decode(encrypted_data)
        return cipher.decrypt(ciphertext).decode()

    def __save_private_key(self, private_key: bytes):
        """Шифрует и сохраняет приватный ключ в JSON-файле."""
        encrypted_key = self.__aes_manager.encrypt(plain_bytes=private_key)
        file_path = "rsa_keys.json"

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

    def __load_private_key(self) -> RSA.RsaKey:
        """Загружает и расшифровывает приватный ключ."""
        file_path = "rsa_keys.json"

        # Проверяем наличие файла
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл {file_path} не найден.")

        # Загружаем данные
        with open(file_path, "r") as file:
            data = json.load(file)
            if self.__key_name in data:
                encrypted_key: str = data[self.__key_name]
                decrypted_key = self.__aes_manager.decrypt(encrypted_key.encode())
                return RSA.import_key(decrypted_key)
            else:
                raise ValueError("Приватный ключ с указанным именем не найден.")

    def __load_public_key(self) -> RSA.RsaKey:
        """Создает публичный ключ из приватного ключа."""
        private_key = self.__load_private_key()
        return private_key.publickey()
