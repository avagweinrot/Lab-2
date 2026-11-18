# crypto_utils.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: 
# https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/ 

import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Initialize path to folder stored locally with private keys in it
KEY_FOLDER = Path(__file__).resolve().parent / "keys"

# Initialize secure padding for encryption
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

# Create a public private key pair
def generate_key_pair():
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
	public_key = private_key.public_key()

	return private_key, public_key

# Converts the public key object into PEM bytes
def serialize_public_key(public_key):
	return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Store private key when a user registers with username and password
def save_private_key(private_key, username, password): 
	KEY_FOLDER.mkdir(parents=True, exist_ok=True)

	# Encrypt private key with the user's password
	pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))


	with open(KEY_FOLDER / (username + ".pem"), "wb") as key_file:
		key_file.write(pem)

# Load a user's private key given their username and password
def load_private_key(username, password): 
	path = KEY_FOLDER / (username + ".pem")
	# None if there is no private key for this user on this machine
	if not path.exists():
		return None 

	# If there is a private key, then load it and read the key
	with open(path, "rb") as key_file:
		return serialization.load_pem_private_key(key_file.read(), password=password.encode())

# Encrypt a message using AESGCM
def encrypt_message(recipient_pem, text):
	# Generate a new AES key for a given message, and turn it into ciphertext
	new_key = AESGCM.generate_key(bit_length=256)
	nonce = os.urandom(12)
	ciphertext = AESGCM(new_key).encrypt(nonce, text.encode(), None)

	# Protect the new AES key with the recipient's public key
	public_key = serialization.load_pem_public_key(recipient_pem)
	encrypted_key = public_key.encrypt(new_key, OAEP)
	return ciphertext, encrypted_key, nonce

# Decrypt a message using AESGCM
def decrypt_message(private_key, ciphertext, encrypted_key, nonce):
	# Decode message using private key
	key = private_key.decrypt(encrypted_key, OAEP)
	plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
	decrypted_message = plaintext.decode()

	return decrypted_message
