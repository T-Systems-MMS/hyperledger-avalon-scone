#!/usr/bin/python3

# Copyright 2020 Intel Corporation
# Copyright 2020 Mujtaba Idrees
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import base64
import logging
import os
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))

# -------------------------------------------------------------------------


class WorkerEncrypt(object):
    """
    Worker Encryption key class.
    """

# -------------------------------------------------------------------------
    # Class variables

    # RSA key size
    RSA_KEY_SIZE = 2048
    # iv size.
    # 96 bits of randomness is recommended to prevent birthday attacks.
    IV_SIZE = 12
    # AES-GCM authenticated tag size
    TAG_SIZE = 16

# -------------------------------------------------------------------------

    def __init__(self):
        """
        Constructor for WorkerEncrypt.
        """
        self.rsa_private_key = None
        self.rsa_public_key = None

# -------------------------------------------------------------------------

    def generate_rsa_key(self):
        """
        Generate 2048 bits RSA key pair.
        """
        #key = RSA.generate(WorkerEncrypt.RSA_KEY_SIZE)
        #self.rsa_private_key = key.export_key()
        #self.rsa_public_key = key.publickey().export_key()
        #print("generated rsa private key : ", self.rsa_private_key)
        #print("generated rsa public key : ", self.rsa_public_key)

        self.rsa_private_key = os.environ["Enc_Pri_Key"]
        self.rsa_public_key = os.environ["Enc_Pub_Key"]

        self.rsa_private_key=self.rsa_private_key.replace("-----BEGIN RSA PRIVATE KEY-----", "start_")
        self.rsa_private_key=self.rsa_private_key.replace("-----END RSA PRIVATE KEY-----", "_end")
        self.rsa_private_key=self.rsa_private_key.replace(" ","\n")
        self.rsa_private_key=self.rsa_private_key.replace("start_", "-----BEGIN RSA PRIVATE KEY-----")
        self.rsa_private_key=self.rsa_private_key.replace( "_end", "-----END RSA PRIVATE KEY-----")
        self.rsa_private_key=self.rsa_private_key.encode("UTF-8")

        self.rsa_public_key=self.rsa_public_key.replace("-----BEGIN PUBLIC KEY-----", "start_")
        self.rsa_public_key=self.rsa_public_key.replace("-----END PUBLIC KEY-----", "_end")
        self.rsa_public_key=self.rsa_public_key.replace(" ","\n")
        self.rsa_public_key=self.rsa_public_key.replace("start_", "-----BEGIN PUBLIC KEY-----")
        self.rsa_public_key=self.rsa_public_key.replace( "_end", "-----END PUBLIC KEY-----")
        self.rsa_public_key=self.rsa_public_key.encode("UTF-8")
        
        #print("CAS rsa private key : ", self.rsa_private_key)
        #print("CAS rsa public key : ", self.rsa_public_key)

# -------------------------------------------------------------------------

    def get_rsa_public_key(self):
        """
        Get RSA Public key.

        Returns :
            RSA Public key stored in the class instance
        """
        return self.rsa_public_key

# -------------------------------------------------------------------------

    def generate_session_key(self):
        """
        Generate 32 bytes random session key.

        Returns :
            32 bytes random session key
        """
        return get_random_bytes(32)

# -------------------------------------------------------------------------

    def generate_iv(self):
        """
        Generate 12 bytes random initialization vector (iv).

        Returns :
            12 bytes random iv
        """
        return get_random_bytes(WorkerEncrypt.IV_SIZE)

# -------------------------------------------------------------------------

    def encrypt_session_key(self, session_key, rsa_public_key=None):
        """
        Decrypt encrypted session key (symmetric key) in bytes
        with RSA private key.

        Parameters :
            enc_session_key: Encrypted session key
            rsa_public_key:  RSA public key. If value passed is None
                             the rsa private key in this class instance
                             is used by default.
        Returns :
            decrypted session key in bytes.
            Raises exception in case of error.
        """
        if rsa_public_key is None:
            rsa_public_key = self.rsa_public_key
        try:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
            enc_session_key = cipher_rsa.encrypt(session_key)
        except Exception as e:
            err_msg = "Encrypt session key failed: " + str(e)
            logger.error(err_msg)
            raise
        return enc_session_key

# -------------------------------------------------------------------------

    def decrypt_session_key(self, enc_session_key, rsa_private_key=None):
        """
        Decrypt encrypted session key (symmetric key) in bytes
        with RSA private key.

        Parameters :
            enc_session_key: Encrypted session key
            rsa_private_key: RSA private key. If value passed is None
                             the rsa private key in this class instance
                             is used by default.
        Returns :
            decrypted session key in bytes.
            Raises exception in case of error.
        """
        if rsa_private_key is None:
            rsa_private_key = self.rsa_private_key
        try:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
            session_key = cipher_rsa.decrypt(enc_session_key)
        except Exception as e:
            err_msg = "Decrypt session key failed: " + str(e)
            logger.error(err_msg)
            raise
        return session_key

# -------------------------------------------------------------------------

    def encrypt_data(self, data_bytes, session_key, iv=None):
        """
        Encrypt (AES-GCM) data bytes with session key (symmetric key).

        Parameters :
            data_bytes: data bytes to encrypt
            session_key: symmetric key used for decryption
            iv: initialization vector corresponding to the session key
                if iv is None then a random 12 bytes iv is generated and
                prepended to the encrypted data.
        Returns :
            encrypted data in bytes.
            Raises exception in case of error.
        """
        # If iv passed is none, generate a random iv
        if iv is None:
            iv = self.generate_iv()
            generate_iv = True
        else:
            generate_iv = False

        try:
            cipher_aes = AES.new(session_key, AES.MODE_GCM, iv)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data_bytes)
        except Exception as e:
            err_msg = "Encrypt data failed: " + str(e)
            logger.error(err_msg)
            raise

        if generate_iv:
            # if iv passed by user is None, iv(generated) is prepended
            # in encrypted data : iv + Cipher + Tag
            result = iv + ciphertext + tag
        else:
            # Cipher + Tag
            result = ciphertext + tag
        return result

# -------------------------------------------------------------------------

    def decrypt_data(self, enc_data_bytes, session_key, iv=None):
        """
        Decrypt (AES-GCM) encrypted data bytes with
        session key (symmetric key).

        Parameters :
            enc_data_bytes: encrypted data in bytes
            session_key: symmetric key used for decryption
            iv: initialization vector corresponding to the session key
                if iv is None the it's assumed that 12 bytes iv is prepended
                to the encrypted data.
        Returns :
            decrypted data in bytes.
            Raises exception in case of error.
        """
        # if iv is None the it's assumed that 12 bytes iv is prepended
        # in encrypted data
        if iv is None:
            iv_length = WorkerEncrypt.IV_SIZE
            iv = enc_data_bytes[:iv_length]
            use_generated_iv = True
        else:
            use_generated_iv = False

        cipher_aes = AES.new(session_key, AES.MODE_GCM, iv)
        tag_size = WorkerEncrypt.TAG_SIZE
        tag = enc_data_bytes[-tag_size:]
        if use_generated_iv:
            ciphertext_len = len(enc_data_bytes) - iv_length - tag_size
            ciphertext = enc_data_bytes[iv_length: iv_length + ciphertext_len]
        else:
            ciphertext_len = len(enc_data_bytes) - tag_size
            ciphertext = enc_data_bytes[: ciphertext_len]

        try:
            result = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            err_msg = "Decrypt data failed: " + str(e)
            logger.error(err_msg)
            raise
        return result

# -------------------------------------------------------------------------

    def decrypt_work_order_data_json(self, data_objects,
                                     session_key, session_iv=None):
        """
        Function to encrypt inData/outData of workorder
        Function iterate through the inData/outData items and
        decrypt the data using DataEncryptionKey/Session key.
        inData/outData data field is updated with decrypted data.

        Parameters:
            data_objects: inData/outData elements within the
                          work order request as per Trusted Compute
                          EEA API 6.1.7 Work Order Data Formats.
            session_key: The key used to decrypt the encrypted data
                         of the response.
            session_iv: initialization vector corresponding
                        to session_key.
        """
        i = 0
        do_decrypt = True
        for item in data_objects:
            data = item['data']
            if 'encryptedDataEncryptionKey' in item:
                e_key = item['encryptedDataEncryptionKey']
            else:
                e_key = None
            if not e_key or (e_key == "null"):
                data_key = session_key
                iv = session_iv
            elif e_key == "-":
                do_decrypt = False
            else:
                if 'iv' in item:
                    iv = item['iv']
                else:
                    iv = None
                # Decrypt data key
                data_key = self.decrypt_data_encryption_key(e_key,
                                                            iv,
                                                            sesssion_key)
            if not do_decrypt:
                item['data'] = self.base64_to_byte_array(data)
            else:
                # Decrypt output data
                item_data_bytes = self.base64_to_byte_array(data)
                data_in_plain = self.decrypt_data(
                    item_data_bytes, data_key, iv)
                item['data'] = data_in_plain
            i = i + 1

# -------------------------------------------------------------------------

    def encrypt_work_order_data_json(self, data_objects,
                                     session_key, session_iv=None):
        """
        Function to encrypt inData/outData of workorder.
        Function iterate through the inData/outData items and
        encrypt the data using DataEncryptionKey/Session key.
        inData/outData data field is updated with enrypted data.

        Parameters:
            data_objects: inData/outData elements within the
                          work order request as per Trusted Compute
                           EEA API 6.1.7 Work Order Data Formats.
            session_key: one-time symmetric encryption key generated by the
                         participant submitting the work order.
            session_iv: initialization vector if required by the
                        data encryption algorithm. The default is None.
        """
        data_objects.sort(key=lambda x: x['index'])
        i = 0
        for item in data_objects:
            data = item['data']
            if 'encryptedDataEncryptionKey' in item:
                e_key = item['encryptedDataEncryptionKey']
            else:
                e_key = None
            if (not e_key) or (e_key == "null"):
                enc_data = self.encrypt_data(
                    data, session_key, session_iv)
                item['data'] = self.byte_array_to_base64(enc_data)
            elif e_key == "-":
                # Skip encryption and just encode workorder data to
                # base64 format.
                item['data'] = self.byte_array_to_base64(data)
            else:
                if 'iv' in item:
                    data_iv = item['iv']
                else:
                    data_iv = None
                # Decrypt data key
                data_key = self.decrypt_data_encryption_key(e_key,
                                                            data_iv,
                                                            sesssion_key)
                enc_data = self.encrypt_data(data, data_key, data_iv)
                item['data'] = self.byte_array_to_base64(enc_data)
            i = i + 1

# -------------------------------------------------------------------------

    def decrypt_data_encryption_key(self, e_key, iv, sesssion_key):
        """
        Decrypts data encryption key in InData/OutData items.
        Based on TC spec v1.1 section 6.5, data encryption key is double
        encrypted. First, it is encrypted with the worker's public encryption
        key. Then the result of the previous encryption above is encrypted with
        session key. This function first decrypts the data encryption key with
        session key and then further decrypts previous result with
        worker's private key.

        Parameters :
            e_key: double encrypted data encryption key
            iv : Initialization vector used to encrypt/decrypt the key
            session_key: one-time symmetric encryption key generated by the
                         participant submitting the work order.
        Returns :
            Decrypted data key in plain bytes.
        """
        first_decrypt_result = self.decrypt_data(e_key, session_key, iv)
        data_key = self.decrypt_session_key(first_decrypt_result,
                                            self.rsa_private_key)

        return data_key

# -------------------------------------------------------------------------

    def encrypt_data_encryption_key(self, data_key, iv, session_key):
        """
        Encrypts data encryption key in InData/OutData items.
        Based on TC spec v1.1 section 6.5, data encryption key is double
        encrypted. First, it is encrypted with the worker's public encryption
        key. Then the result of the previous encryption above is encrypted with
        session key.

        Parameters :
            data_key: data key in bytes
            iv : Initialization vector used to encrypt/decrypt the key
            session_key: one-time symmetric encryption key generated by the
                         participant submitting the work order.
        Returns :
            Encrypted data key in plain bytes.
        """
        first_encrypt_result = self.encrypt_session_key(data_key,
                                                        self.rsa_public_key)
        e_key = self.encrypt_data(first_encrypt_result, session_key, iv)

        return e_key

# -------------------------------------------------------------------------

    def base64_to_byte_array(self, b64_str):
        """
        Decode Base64 string to bytes.

        Parameters :
            b64_str: Base64 encoded string
        Returns :
            base64 decoded data in bytes.
        """
        try:
            b64_bytes = b64_str.encode('UTF-8')
            b64_dec_bytes = base64.b64decode(b64_bytes)
            return b64_dec_bytes
        except Exception as e:
            err_msg = "base64 string decode to byte array failed: " + str(e)
            logger.error(err_msg)
            raise

# -------------------------------------------------------------------------

    def byte_array_to_base64(self, data_bytes):
        """
        Converts bytes to Base64 encoded string.

        Parameters :
            data_bytes: data to be encoded in bytes
        Returns :
            Base64 encoded string.
        """
        try:
            b64 = base64.b64encode(data_bytes)
            b64_str = b64.decode('UTF-8')
            return b64_str
        except Exception as e:
            err_msg = "byte array to base64 encode string failed: " + str(e)
            logger.error(err_msg)
            raise

# -------------------------------------------------------------------------
