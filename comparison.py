import hashlib
import bcrypt
import time

# passwords = ['hello', 'pass', 'coding', '1234', 'password', 'password123', 'password123456', 'password123456789',
#              'password123456789012', 'password123456789012345', 'password', 'password', 'password', 'password',
#              'password', 'password', 'password', 'password', 'password', 'password', 'password', 'password',
#              'password', 'password', 'password', 'password', 'password', 'password', 'password', 'password',
#              'password', 'password', 'password', 'password', 'password', 'password', 'password', 'password',
#              'password', 'password', 'password', 'password', 'password', 'password', 'password', 'password',
#              'password', 'password', 'password', 'password', 'password', 'password', 'password', 'password',]

passwords = ['hello', 'pass', 'coding', '1234', 'password']

characters = 'abcdefghijklmnopqrstuvwxyz0123456789'

def md5(password):
    for password in passwords:
        hashlib.md5(password.encode()).hexdigest()

def sha256(password):
    for password in passwords:
        hashlib.sha256(password.encode()).hexdigest()

def sha512(password):
    for password in passwords:
        hashlib.sha512(password.encode()).hexdigest()

def bcrypt_func(password):
    for password in passwords:
        bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def pbkdf2(password):
    for password in passwords:
        hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000)

def measure_time(hash_func, passwords):
    start = time.time()
    hashed_passwords = hash_func(passwords)
    end = time.time()
    # print(f"Hashing time: {end - start:.6f} seconds")
    # return hashed_passwords
    return (f"{end - start:.6f} seconds")

def times():
    print('MD5: ', measure_time(md5, passwords))
    print('SHA-256: ', measure_time(sha256, passwords))
    print('SHA-512: ', measure_time(sha512, passwords))
    print('Bcrypt: ', measure_time(bcrypt_func, passwords))
    print('PBKDF2: ', measure_time(pbkdf2, passwords))

if __name__ == '__main__':
    times()
