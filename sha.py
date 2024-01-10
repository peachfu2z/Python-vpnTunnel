import hmac
import hashlib

class HMACVerifier:
    def __init__(self, key, hash_algorithm=hashlib.sha256):
        self.key = str(key).encode()
        self.hash_algorithm = hash_algorithm

    def generate_hmac(self, data):
        """generate HMAC"""
        hmac_result = hmac.new(self.key, data, self.hash_algorithm).digest()
        return hmac_result

    def verify_hmac(self, data, expected_hmac):
        """verify HMAC"""
        current_hmac = self.generate_hmac(data)
        return hmac.compare_digest(current_hmac, expected_hmac)

