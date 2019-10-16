#imports
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#starter
print (u"\u001b[36;1m######################")
print ("#WELCOME TO PY-CRYPTO#")
print ("######################\u001b[0m")

#functions
def getKey():
	salt = os.urandom(16)
	password_provided = input("Enter a password: ") # This is input in the form of a string
	password = password_provided.encode() # Convert to type bytes
	salt = salt # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
	   	iterations=100000,
	   	backend=default_backend()
	)
	key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

	finkey = key.decode()

	print (finkey)

def encrypt():
	message = input("Enter a message to encrypt: ").encode()

	keywant = input("Enter the key to encrypt the message: ")

	f = Fernet(keywant)
	encrypted = f.encrypt(message)

	finenc = encrypted.decode()

	print (finenc)


def decrypt():
	encrypmsg = input('Enter the encrypted message: ')
	enc1 = bytes(encrypmsg, 'ascii')

	keyused = input("Enter the key: ")


	f2 = Fernet(keyused)
	decoded = f2.decrypt(enc1)

	findec = decoded.decode()

	print(findec)

#real stuff
while True:
	com = input("Enter a command: ")

	if com == "key":
		getKey()


	elif com == "quit":
		break

	elif com == "help":
		print ("Enter quit to quit")
		print ("Enter key to generate a key from a password")
		print ("Enter encrypt to encrypt a message")
		print ("Enter decrypt to decrypt a message")
		print ("enter info for more information")


	elif com == "info":
		print ("This is a program that encrypts and decrypts messages")
		print ("Written in: python")
		print ("Creator: V01D-7")
		print ("Encryption method: AES and SHA256")

	elif com == "encrypt":
		encrypt()

	elif com == "decrypt":
		decrypt()

#thanks for downloading!
