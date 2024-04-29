from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from os import urandom

class AESEncryptor:
    def __init__(self):
        self.key, self.iv = AESEncryptor.generateRandomKeyIv(16)
        self.backend = default_backend()

    @staticmethod
    def generateRandomKeyIv(byte):
        key = urandom(byte)
        iv = urandom(byte)

        return key, iv

    def getBase64KeyIv(self):
        base64Key = b64encode(self.key).decode()
        base64Iv = b64encode(self.iv).decode()
        return base64Key, base64Iv

    def encryptAESCBC(self, plaintext):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        paddedData = padder.update(plaintext) + padder.finalize()
        
        ciphertext = encryptor.update(paddedData) + encryptor.finalize()
        
        return ciphertext

    def decryptAESCBC(self, ciphertext):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
        decryptor = cipher.decryptor()

        decryptedData = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpaddedData = unpadder.update(decryptedData) + unpadder.finalize()

        return unpaddedData.decode()

    def getBase64encryptedAESCBC(self, ciphertext):
        base64Ciphertext = b64encode(ciphertext).decode()
        return base64Ciphertext