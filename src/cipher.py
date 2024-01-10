import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES, DES3,DES
import random
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
'''AES_CBC'''
class AESCipher: 
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        self.iv = get_random_bytes(AES.block_size)  # 随机生成IV
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        encrypted_data = cipher.encrypt(raw)
        return self.iv + encrypted_data

    def decrypt(self, msg):
        self.iv = msg[:AES.block_size]  # 从加密数据中提取IV
        encrypted_data = msg[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return self._unpad(decrypted_data)

    def _pad(self, data):
        try:
            return pad(data, AES.block_size)
        except Exception as e:
            print(f"Error in AES padding: {e}")
            pass

    @staticmethod
    def _unpad(data):
        try:
            return unpad(data, AES.block_size)
        except Exception as e:
            print(f"Error in AES unpadding: {e}")
            pass

'''3DES_CBC'''
class TripleDESCipher_CBC:
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        self.iv = get_random_bytes(DES3.block_size)  # 随机生成IV
        raw = self._pad(raw)
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv=self.iv)
        encrypted_data = cipher.encrypt(raw)
        return self.iv + encrypted_data

    def decrypt(self, msg):
        self.iv = msg[:DES3.block_size]  # 从加密数据中提取IV
        encrypted_data = msg[DES3.block_size:]
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv=self.iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return self._unpad(decrypted_data)

    def _pad(self, data):
        try:
            return pad(data, DES3.block_size)
        except Exception as e:
            print(f"Error in 3DES padding: {e}")
            pass

    @staticmethod
    def _unpad(data):
        try:
            return unpad(data, DES3.block_size)
        except Exception as e:
            print(f"Error in 3DES unpadding: {e}")
            pass

'''DES_CBC'''
class DESCipher_CBC:
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        self.iv = get_random_bytes(DES.block_size)  # 随机生成IV
        raw = self._pad(raw)
        cipher = DES.new(self.key, DES.MODE_CBC, iv=self.iv)
        encrypted_data = cipher.encrypt(raw)
        return self.iv + encrypted_data

    def decrypt(self, msg):
        self.iv = msg[:DES.block_size]  # 从加密数据中提取IV
        encrypted_data = msg[DES.block_size:]
        cipher = DES.new(self.key, DES.MODE_CBC, iv=self.iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return self._unpad(decrypted_data)

    def _pad(self, data):
        try:
            return pad(data, DES.block_size)
        except Exception as e:
            print(f"Error in DES padding: {e}")
            pass

    @staticmethod
    def _unpad(data):
        try:
            return unpad(data, DES.block_size)
        except Exception as e:
            print(f"Error in DES unpadding: {e}")
            pass
    
    
