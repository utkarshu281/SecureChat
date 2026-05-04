import bcrypt
from cryptography.fernet import Fernet
from config import KEY_FILE

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

def load_key():
    try:
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        generate_key()
        return load_key()

def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt_message(blob):
    key = load_key()
    f = Fernet(key)
    return f.decrypt(blob.encode()).decode()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())