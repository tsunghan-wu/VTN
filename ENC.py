from Crypto.Cipher import AES
import os

def pad(message):
    return message+bytes([(16-len(message)%16) for i in range(16-len(message)%16)])

def unpad(message):
    return message[:-message[-1]]

def Encrypt(message, key):
    IV = os.urandom(16)
    message = pad(message)
    cipher = AES.new(key,AES.MODE_CBC,IV)
    ciphertext = cipher.encrypt(message)
    Cmessage = IV+ciphertext
    return Cmessage

def Decrypt(message, key):
    print(message)
    IV = message[:16]
    print(IV)
    cipher = AES.new(key,AES.MODE_CBC,IV)
    plaintext = cipher.decrypt(message[16:])
    plaintext = unpad(plaintext)
    return plaintext
