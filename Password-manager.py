import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_FILE = "salt.bin"
VAULT_FILE = "vault.json"


def generate_key(master_password: str, salt: bytes) -> bytes:
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,  
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)


def load_or_create_salt() -> bytes:
    """Loads existing salt, or creates+saves a new one on first run."""
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt


def load_vault() -> dict:
    """Loads the vault JSON, or returns an empty dict if it doesn't exist yet."""
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as f:
            return json.load(f)
    return {}


def save_vault(vault: dict):
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=4)


def add_entry(vault: dict, fernet: Fernet):
    print("Enter your service name:")
    service = input().strip()
    print("Enter your username:")
    username = input().strip()
    print("Enter your password:")
    password = input().strip()

    encrypted_password = fernet.encrypt(password.encode())
    encrypted_str = encrypted_password.decode()

    vault[service] = {"username": username, "password": encrypted_str}
    save_vault(vault)
    print(f"Saved entry for {service}.")


def view_entry(vault: dict, fernet: Fernet):
    service = input("Service to view: ").strip()
    if service not in vault:
        print("Service not found.")
        return
    entry = vault[service]
    stored_password = entry.get("password", "")
    try:
        decrypted = fernet.decrypt(stored_password.encode()).decode()
    except Exception:
        print("Failed to decrypt password. Wrong master password or corrupted data.")
        return
    print(f"Username: {entry.get('username', '')}\nPassword: {decrypted}")


def list_entries(vault: dict):
    if not vault:
        print("Vault is empty.")
        return
    for service in vault:
        print(f"- {service}")


def delete_entry(vault: dict):
    service = input("Service to delete: ")
    if service in vault:
        del vault[service]
        save_vault(vault)
        print(f"Deleted {service}.")
    else:
        print("Service not found.")


def main():
    salt = load_or_create_salt()
    master_password = input("Enter master password: ")
    key = generate_key(master_password, salt)
    fernet = Fernet(key)

    vault = load_vault()

    while True:
        print("\n1. Add entry\n2. View entry\n3. List services\n4. Delete entry\n5. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            add_entry(vault, fernet)
        elif choice == "2":
            view_entry(vault, fernet)
        elif choice == "3":
            list_entries(vault)
        elif choice == "4":
            delete_entry(vault)
        elif choice == "5":
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()