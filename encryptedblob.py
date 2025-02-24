import base64
import os
import hmac
import hashlib
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import imexceptions

class EncryptedBlob:

    def __init__(self, plaintext=None, confkey=None, authkey=None): 
        self.plaintext = plaintext
        self.ivBase64 = None
        self.ciphertextBase64 = None
        self.macBase64 = None

        if plaintext is not None:
            self.ivBase64, self.ciphertextBase64, self.macBase64 = self.encryptThenMAC(confkey, authkey, plaintext)

    def encryptThenMAC(self, confkey, authkey, plaintext):
        # Generate a random IV 
        iv = os.urandom(16)
        
        # Pad plaintext and encrypt it
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        plaintextPadded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(plaintextPadded)
        
        # Compute HMAC-SHA256 for integrity
        mac = hmac.new(authkey, iv + ciphertext, hashlib.sha256).digest()
        
        # Convert IV, ciphertext, and MAC to Base64 for JSON compatibility
        ivBase64 = base64.b64encode(iv).decode('utf-8')
        ciphertextBase64 = base64.b64encode(ciphertext).decode('utf-8')
        macBase64 = base64.b64encode(mac).decode('utf-8')
        
        return ivBase64, ciphertextBase64, macBase64

    def decryptAndVerify(self, confkey, authkey, ivBase64, ciphertextBase64, macBase64):
        # Decode Base64 inputs
        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        received_mac = base64.b64decode(macBase64)
        
        # Recompute HMAC-SHA256 for verification
        computed_mac = hmac.new(authkey, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(received_mac, computed_mac):
            raise imexceptions.FailedAuthenticationError("MAC verification failed!")
        
        # Decrypt ciphertext
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        plaintextPadded = cipher.decrypt(ciphertext)
        
        try:
            plaintext = unpad(plaintextPadded, AES.block_size).decode('utf-8')
        except ValueError:
            raise imexceptions.FailedDecryptionError("Decryption failed due to incorrect padding!")
        
        return plaintext