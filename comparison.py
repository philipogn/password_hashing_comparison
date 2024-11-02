import hashlib
import bcrypt
from argon2 import PasswordHasher
import time

passwords = ['hello', 'pass', 'coding', '1234', 'password', 'password123', 'steve123', 'coolpassword', 'password1234', 'helloworld',
             'BrightSky92', 'CoffeeMug247', 'OceanBreeze8', 'SunnyDay101', 'RiverFlow72', 'GreenLeaf2023', 'HappyCat77', 'CalmLake3',
             'SilverMoon915', 'BlueSkybox4', 'MagicSnow16', 'RainyNight22', 'LuckyStar13', 'DreamWave84', 'WarmSunlight9',
             'FreshMint64', 'QuietTree291', 'MorningTea5', 'GoldenHills32', 'PeacefulSoul48'
             ]

# passwords = ['hello', 'pass', 'coding', '1234', 'password']

characters = 'abcdefghijklmnopqrstuvwxyz0123456789'

def bcrypt_func(password):
    for password in passwords:
        bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def pbkdf2(password):
    for password in passwords:
        hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000)

def argon2_func(password):
    for password in passwords:
        ph = PasswordHasher()
        ph.hash(password)

def measure_time(hash_func, passwords):
    start_time = time.perf_counter()
    hash_func(passwords)
    end_time = time.perf_counter()
    return (f'{end_time - start_time:.6f} seconds')

def times():
    print('Bcrypt:', measure_time(bcrypt_func, passwords))
    print('PBKDF2:', measure_time(pbkdf2, passwords))
    print('Argon2:', measure_time(argon2_func, passwords))

if __name__ == '__main__':
    times()
