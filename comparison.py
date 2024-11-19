import hashlib
import bcrypt
import scrypt
from argon2 import PasswordHasher
import time
import psutil

passwords = ['hello', 'pass', 'coding', '1234', 'password', 'password123', 'steve123', 'coolpassword', 'password1234', 'helloworld',
             'BrightSky92', 'CoffeeMug247', 'OceanBreeze8', 'SunnyDay101', 'RiverFlow72', 'GreenLeaf2023', 'HappyCat77', 'CalmLake3',
             'SilverMoon915', 'BlueSkybox4', 'MagicSnow16', 'RainyNight22', 'LuckyStar13', 'DreamWave84', 'WarmSunlight9',
             'FreshMint64', 'QuietTree291', 'MorningTea5', 'GoldenHills32', 'PeacefulSoul48'
             ]

# passwords = ['helloworld12', 'coding642', '12345', 'password784', 'sunnyhill22', 'flowingriver63', 'greenleaf2023', 'happycat77', 
#              'calmlake3', 'silvermoon915']

characters = 'abcdefghijklmnopqrstuvwxyz0123456789'

def argon2_hash(passwords):
    for word in passwords:
        ph = PasswordHasher()
        ph.hash(word)

def pbkdf2_hash(passwords):
    for word in passwords:
        hashlib.pbkdf2_hmac('sha256', word.encode(), b'salt', 100000)

def bcrypt_hash(passwords):
    for word in passwords:
        bcrypt.hashpw(word.encode(), bcrypt.gensalt())

def scrypt_hash(passwords):
    for word in passwords:
        scrypt.hash(word, b'salt', N=2**14, r=8, p=5)

def measure_time(hash_func, words):
    start_time = time.perf_counter()
    hash_func(words)
    memory_usage = psutil.Process().memory_info().rss / (1024 * 1024)  # convert to MB
    end_time = time.perf_counter()
    return (f'Time: {end_time - start_time:.6f} seconds, Memory: {memory_usage:.2f} MB')

def times():
    print('Argon2 -', measure_time(argon2_hash, passwords))
    print('Bcrypt -', measure_time(bcrypt_hash, passwords))
    print('PBKDF2 -', measure_time(pbkdf2_hash, passwords))
    print('Scrypt -', measure_time(scrypt_hash, passwords))

if __name__ == '__main__':
    times()