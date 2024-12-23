from utils import AESManager

if __name__ == "__main__":
    # Создаем ключ с правильным паролем
    key_name = "example_key"
    correct_password = "correct_password"
    wrong_password = "wrong_password"
    print("=== Проверка с неправильным паролем при загрузке ===")
    try:
        manager_wrong = AESManager(key_name, correct_password)
        loaded_key = manager_wrong._AESManager__load_key()
        print(f"Ключ успешно загружен: {loaded_key.hex()}")
    except ValueError as e:
        print(f"Ошибка при загрузке ключа: {e}")
