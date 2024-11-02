import hashlib
import bcrypt
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

def sha512_hash(passwords):
    for word in passwords:
        hashlib.sha512(word.encode()).hexdigest()

def bcrypt_hash(passwords):
    for word in passwords:
        bcrypt.hashpw(word.encode(), bcrypt.gensalt())

def pbkdf2_hash(passwords):
    for word in passwords:
        hashlib.pbkdf2_hmac('sha256', word.encode(), b'salt', 100000)

def argon2_hash(passwords):
    for word in passwords:
        ph = PasswordHasher()
        ph.hash(word)

def measure_time(hash_func, words):
    start_time = time.perf_counter()
    hash_func(words)
    end_time = time.perf_counter()
    return (f'{end_time - start_time:.6f} seconds')

def times():
    print('SHA512 - Time:', measure_time(sha512_hash, passwords), ', Memory:', psutil.Process().memory_info().rss)
    print('Bcrypt - Time:', measure_time(bcrypt_hash, passwords), ', Memory:', psutil.Process().memory_info().rss)
    print('PBKDF2 - Time:', measure_time(pbkdf2_hash, passwords), ', Memory:', psutil.Process().memory_info().rss)
    print('Argon2 - Time:', measure_time(argon2_hash, passwords), ', Memory:', psutil.Process().memory_info().rss)

if __name__ == '__main__':
    times()
    # print(run_benchmark())