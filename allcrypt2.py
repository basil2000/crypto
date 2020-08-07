import os

# Specify the path
path = 'C:/Python/Python38/PYTHON PROGRAMS'

# Specify the file name
file = 'encryptedfile.txt'

# Creating a file at specified location
with open(os.path.join(path, file), 'wb') as fp:
    pass


def numbers_to_strings(argument):
    switcher = {
        1: "AES",
        2: "Triple DES",
        3: "md5",
        4: "RSA",
    }
    return switcher.get(argument, "nothing")


def main():
    n = int(input("what encryption algorithm to use ?\n1.AES\n2.DES\n3.md5\n4.RSA\n"))
    string = numbers_to_strings(n)

    if n == 1:
        print(string + " chosen\n")
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        file1 = open("C:\Python\Python38\PYTHON PROGRAMS\hello.txt", "r")
        file2 = open("C:\Python\Python38\PYTHON PROGRAMS\encryptedfile.txt", "wb")
        for line in file1.readlines():
            cipher_text = cipher_suite.encrypt(line.encode())
            file2.write(cipher_text)
        file1.close()
        file2.close()

    elif n == 2:
        print(string + " chosen\n")
        import TDES
        k = TDES.triple_des("ACTIONFI        yoyoyoyo", 1, "\0\0\0\0\0\0\0\0", pad=None, padmode=2)
        file1 = open("C:\Python\Python38\PYTHON PROGRAMS\hello.txt", "r")
        file2 = open("C:\Python\Python38\PYTHON PROGRAMS\encryptedfile.txt", "wb")
        for line in file1.readlines():
            d = k.encrypt(line)
            file2.write(d)
        file1.close()

    elif n == 3:
        print(string + " chosen\n")
        import hashlib
        file1 = open("C:\Python\Python38\PYTHON PROGRAMS\hello.txt", "r")
        file2 = open("C:\Python\Python38\PYTHON PROGRAMS\encryptedfile.txt", "wb")
        for line in file1.readlines():
            result = hashlib.md5(line.encode())
            file2.write(result.digest())
        file1.close()

    elif n == 4:
        print(string + " chosen\n")
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5
        from Crypto.Random import new as Random
        from base64 import b64encode
        from base64 import b64decode

        class RSACipher:
            def generate_key(self, key_length):
                assert key_length in [1024, 2048, 4096]
                rng = Random().read
                self.key = RSA.generate(key_length, rng)

            def encrypt(self, data):
                plaintext = b64encode(data.encode())
                rsa_encryption_cipher = PKCS1_v1_5.new(self.key)
                ciphertext = rsa_encryption_cipher.encrypt(plaintext)
                return b64encode(ciphertext).decode()

            def decrypt(self, data):
                ciphertext = b64decode(data.encode())
                rsa_decryption_cipher = PKCS1_v1_5.new(self.key)
                plaintext = rsa_decryption_cipher.decrypt(ciphertext, 16)
                return b64decode(plaintext).decode()

        cipher = RSACipher()
        cipher.generate_key(1024)  # key length can be 1024, 2048 or 4096
        file1 = open("C:\Python\Python38\PYTHON PROGRAMS\hello.txt", "r")
        file2 = open("C:\Python\Python38\PYTHON PROGRAMS\encryptedfile.txt", "w")
        for line in file1.readlines():
            line2 = cipher.encrypt(line)
            print(line2)
            file2.write(line2)
        file1.close()
        file2.close()
    else:
        print("goodbye\n")


main()
