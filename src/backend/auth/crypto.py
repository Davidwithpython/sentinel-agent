from cryptography.fernet import Fernet
from config.config import CRYPTOGRAPHY_SECRET_KEY

# Load key from environment (BEST PRACTICE)
SECRET_KEY = CRYPTOGRAPHY_SECRET_KEY
cipher = Fernet(SECRET_KEY)


def encrypt_data(data: str) -> str:
    if not data:
        return None
    return cipher.encrypt(data.encode()).decode()


def decrypt_data(data: str) -> str:
    if not data:
        return None
    return cipher.decrypt(data.encode()).decode()