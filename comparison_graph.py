import hashlib
import bcrypt
import scrypt
import psutil
import time
from argon2 import PasswordHasher
import matplotlib.pyplot as plt

passwords = ['hello', 'pass', 'coding', '1234', 'password', 'password123', 'steve123', 'coolpassword', 'password1234', 'helloworld',
             'BrightSky92', 'CoffeeMug247', 'OceanBreeze8', 'SunnyDay101', 'RiverFlow72', 'GreenLeaf2023', 'HappyCat77', 'CalmLake3',
             'SilverMoon915', 'BlueSkybox4', 'MagicSnow16', 'RainyNight22', 'LuckyStar13', 'DreamWave84', 'WarmSunlight9',
             'FreshMint64', 'QuietTree291', 'MorningTea5', 'GoldenHills32', 'PeacefulSoul48', 'hello', 'pass', 'coding', '1234', 'password', 'password123', 'steve123', 'coolpassword', 'password1234', 'helloworld',
             'BrightSky92', 'CoffeeMug247', 'OceanBreeze8', 'SunnyDay101', 'RiverFlow72', 'GreenLeaf2023', 'HappyCat77', 'CalmLake3',
             'SilverMoon915', 'BlueSkybox4', 'MagicSnow16', 'RainyNight22', 'LuckyStar13', 'DreamWave84', 'WarmSunlight9',
             'FreshMint64', 'QuietTree291', 'MorningTea5', 'GoldenHills32', 'PeacefulSoul48']

# passwords = ["hello", "coding123", "password123", "helloworld"]

def argon2_hash(passwords):
    ph = PasswordHasher(time_cost=10, memory_cost=65536, parallelism=4)  # Higher time and memory cost, parallelism
  # Adjusted parameters
    for word in passwords:
        ph.hash(word)

def bcrypt_hash(passwords):
    for word in passwords:
        bcrypt.hashpw(word.encode(), bcrypt.gensalt(rounds=9))  # Adjusted rounds

def pbkdf2_hash(passwords):
    for word in passwords:
        hashlib.pbkdf2_hmac('sha256', word.encode(), b'salt', 600000)  # Adjusted iterations

def scrypt_hash(passwords):
    for word in passwords:
        scrypt.hash(word, b'salt', N=2**14, r=8, p=5)

# Measure execution time
def measure_time(hash_func, words):
    start_time = time.perf_counter()
    hash_func(words)
    end_time = time.perf_counter()
    return end_time - start_time

def run_time():
    for func in [argon2_hash, bcrypt_hash, pbkdf2_hash, scrypt_hash]:
        exec_time = measure_time(func, passwords)
        memory_usage = psutil.Process().memory_info().rss / (1024 * 1024)  # convert to MB
        print(f'{func.__name__} - Time: {exec_time:.4f} seconds, Memory: {memory_usage:.2f} MB')

# Measure performance and plot
def times_and_plot():
    algorithms = ['Argon2', 'Bcrypt', 'PBKDF2', 'Scrypt']
    times = []
    memory_usages = []

    # measure time and memory usage
    for func in [argon2_hash, bcrypt_hash, pbkdf2_hash, scrypt_hash]:
        exec_time = measure_time(func, passwords)
        memory_usage = psutil.Process().memory_info().rss / (1024 * 1024)  # convert to MB
        times.append(exec_time)
        memory_usages.append(memory_usage)
        print(f'{func.__name__} - Time: {exec_time:.4f} seconds, Memory: {memory_usage:.2f} MB')

    # plot graph
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Bar plot for execution time
    ax1.bar(algorithms, times, color='skyblue')
    ax1.set_xlabel('Hashing Algorithms')
    ax1.set_ylabel('Execution Time (seconds)', color='blue')
    ax1.tick_params(axis='y', labelcolor='blue')

    # secondary y-axis for memory usage
    ax2 = ax1.twinx()
    ax2.plot(algorithms, memory_usages, color='red', marker='o', linestyle='dashed', linewidth=2)
    ax2.set_ylabel('Memory Usage (MB)', color='red')
    ax2.tick_params(axis='y', labelcolor='red')

    plt.title('Execution Time and Memory Usage of Password Hashing Algorithms')
    plt.show()

run_time()
# times_and_plot()
