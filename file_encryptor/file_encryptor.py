import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


class FileEncryptor:
    def __init__(self, key, iv):
        self.key = self._validate_key(key)
        self.iv = self._validate_iv(iv)
        self.backend = default_backend()

    def _validate_key(self, key):
        if isinstance(key, str):
            key = key.encode('utf-8')

        key_lengths = {16: 16, 24: 24, 32: 32}
        if len(key) not in key_lengths:
            key = hashlib.sha256(key).digest()[:32]

        return key

    def _validate_iv(self, iv):

        if isinstance(iv, str):
            iv = iv.encode('utf-8')

        if len(iv) != 16:
            iv = hashlib.sha256(iv).digest()[:16]
        return iv

    def _pad_data(self, data):

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    def _unpad_data(self, padded_data):

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    def encrypt_file(self, input_file, output_file, mode='ecb'):

        with open(input_file, 'rb') as f:
            data = f.read()

        padded_data = self._pad_data(data)

        if mode.lower() == 'ecb':
            cipher = Cipher(algorithms.AES(self.key),
                            modes.ECB(), backend=self.backend)
        elif mode.lower() == 'cbc':
            cipher = Cipher(algorithms.AES(self.key),
                            modes.CBC(self.iv), backend=self.backend)
        else:
            raise ValueError("Unsupported mode. Use 'ecb' or 'cbc'.")

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_file, output_file, mode='ecb'):

        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        if mode.lower() == 'ecb':
            cipher = Cipher(algorithms.AES(self.key),
                            modes.ECB(), backend=self.backend)
        elif mode.lower() == 'cbc':
            cipher = Cipher(algorithms.AES(self.key),
                            modes.CBC(self.iv), backend=self.backend)
        else:
            raise ValueError("Unsupported mode. Use 'ecb' or 'cbc'.")

        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(
            encrypted_data) + decryptor.finalize()

        decrypted_data = self._unpad_data(decrypted_padded_data)

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

    @staticmethod
    def verify_file_integrity(original_file, decrypted_file):

        def _file_hash(filepath):
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()

        original_hash = _file_hash(original_file)
        decrypted_hash = _file_hash(decrypted_file)

        return original_hash == decrypted_hash
