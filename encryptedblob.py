import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import imexceptions


class EncryptedBlob:

    # the constructor
    def __init__(self, plaintext=None, confkey=None, authkey=None): 
        self.plaintext = plaintext
        self.ivBase64 = None
        self.ciphertextBase64 = None
        self.macBase64 = None

        if plaintext is not None:
            self.ivBase64, self.ciphertextBase64, self.macBase64 = self.encryptThenMAC(confkey, authkey, plaintext)



    # encrypts the plaintext and adds a SHA256-based HMAC
    # using an encrypt-then-MAC solution
    def encryptThenMAC(self,confkey,authkey,plaintext):
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY ENCRYPT 
        # AND GENERATE A SHA256-BASED HMAC BASED ON THE 
        # confkey AND authkey
        iv = get_random_bytes(16)


        # pad the plaintext to make AES happy
        confkey_bytes = bytes(confkey, 'ascii')
        authkey_bytes = bytes(authkey, 'ascii')

        # Pad the plaintext
        plaintext_padded = pad(plaintext.encode('utf-8'), AES.block_size)

        # Encrypt using AES-CBC
        cipher = AES.new(confkey_bytes, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext_padded)

        # Compute HMAC using SHA-256 on (IV || Ciphertext)
        hmac = HMAC.new(authkey_bytes, digestmod=SHA256)
        hmac.update(iv + ciphertext)
        mac = hmac.digest()

        # DON'T CHANGE THE BELOW.
        # What we're doing here is converting the iv, ciphertext,
        # and mac (which are all in bytes) to base64 encoding, so that it 
        # can be part of the JSON EncryptedIM object
        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(mac).decode("utf-8") 
        return ivBase64, ciphertextBase64, macBase64


    def decryptAndVerify(self,confkey,authkey,ivBase64,ciphertextBase64,macBase64):
        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        mac = base64.b64decode(macBase64)
        
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY DECRYPT
        # IF IT DOESN'T DECRYPT, YOU NEED TO RAISE A 
        # FailedDecryptionError EXCEPTION
        confkey_bytes = bytes(confkey, 'ascii')
        authkey_bytes = bytes(authkey, 'ascii')

        hmac = HMAC.new(authkey_bytes, digestmod=SHA256)
        hmac.update(iv + ciphertext)

    
        # TODO: hint: in encryptThenMAC, I padded the plaintext.  You'll
        # need to unpad it.
        # See https://pycryptodome.readthedocs.io/en/v3.11.0/src/util/util.html#crypto-util-padding-module

        # so, this next line is definitely wrong.  :)
        
        # TODO: DON'T FORGET TO VERIFY THE MAC!!!
        # IF IT DOESN'T VERIFY, YOU NEED TO RAISE A
        # FailedAuthenticationError EXCEPTION
        try:
            hmac.verify(received_mac)
        except ValueError:
            raise imexceptions.FailedAuthenticationError("MAC verification failed")

        # Decrypt using AES-CBC
        cipher = AES.new(confkey_bytes, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext)

        # Remove padding
        try:
            plaintext = unpad(plaintext_padded, AES.block_size).decode('utf-8')
        except ValueError:
            raise imexceptions.FailedDecryptionError("Ruh oh")

        

        return self.plaintext
