import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from file_encryptor.file_encryptor import FileEncryptor

def main():
    # Define a secure encryption key (16, 24, or 32 bytes)
    key = b'MyVerySecretKey123!'
    
    # Initialization Vector (must be 16 bytes)
    iv = b'MySecureIVVector16'
    
    # Create the file encryptor
    encryptor = FileEncryptor(key, iv)
    
    try:
        # Encrypt in CBC/ECB mode
        encryptor.encrypt_file('test/secret.txt', 'test/encrypted_files/encrypted_secret.txt', mode='ecb')
        print(f"File is encrypted in the 'encrypted_files' folder!")
        
        # Decrypt the file
        #encryptor.decrypt_file('test/encrypted_files/encrypted_secret.txt', 'test/decrypted_files/decrypted_secret.txt', mode='ecb')
        #print(f"File is decrypted in the 'decrypted_files' folder!")
        
        # Verify file integrity
        #is_intact_1 = FileEncryptor.verify_file_integrity('test/secret.txt', 'test/decrypted_files/decrypted_secret.txt')
        #print(f"File integrity verified: {is_intact_1}")
        #is_intact_2 = FileEncryptor.verify_file_integrity('test/invalid_secret.txt', 'test/decrypted_files/decrypted_secret.txt')
        #print(f"File integrity verified: {is_intact_2}")
        
    
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()