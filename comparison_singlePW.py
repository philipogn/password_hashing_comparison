import hashlib
import bcrypt
import scrypt
import psutil
import time
from argon2 import PasswordHasher
import matplotlib.pyplot as plt

password = "password1234!"

def argon2_hash(password):
    ph = PasswordHasher(time_cost=1, memory_cost=47104, parallelism=1)  # Higher time and memory cost, parallelism
    ph.hash(password)

def bcrypt_hash(password):
    bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=9))  # Adjusted rounds

def scrypt_hash(password):
    scrypt.hash(password, b'salt', N=2**17, r=8, p=1)

def pbkdf2_hash(password):
    hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 600000)  # Adjusted iterations

# Measure execution time
def measure_time(hash_func, words):
    start_time = time.perf_counter()
    hash_func(words)
    end_time = time.perf_counter()
    return end_time - start_time

# Run the test multiple times and average the results
def measure_performance(hash_func, passwords, runs=None):
    times = []
    memory_usages = []
    
    for _ in range(runs):
        process = psutil.Process()
        memory_before = process.memory_info().rss / (1024 * 1024)  # Convert to MB
        
        exec_time = measure_time(hash_func, passwords)
        
        memory_after = process.memory_info().rss / (1024 * 1024)  # Convert to MB
        memory_usage = memory_after

        times.append(exec_time)
        memory_usages.append(memory_usage)
    
    avg_time = sum(times) / len(times)
    avg_memory = sum(memory_usages) / len(memory_usages)
    return avg_time, avg_memory

# measure performance and plot
def times_and_plot():
    algorithms = ['Argon2', 'Bcrypt', 'Scrypt', 'PBKDF2']
    hash_funcs = [argon2_hash, bcrypt_hash, scrypt_hash, pbkdf2_hash]
    avg_times = []
    avg_memories = []

    for func in hash_funcs:
        avg_time, avg_memory = measure_performance(func, password, runs=100)
        avg_times.append(avg_time)
        avg_memories.append(avg_memory)
        print(f'{func.__name__} - Avg Time: {avg_time:.4f} seconds, Avg Memory: {avg_memory:.2f} MB')

    # Plot graph
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Bar plot for execution time
    ax1.bar(algorithms, avg_times, color='skyblue', zorder=2, label='Execution Time')
    ax1.set_xlabel('Hashing Algorithms')
    ax1.set_ylabel('Execution Time (seconds)', color='blue')
    ax1.tick_params(axis='y', labelcolor='blue')

    # Add grid lines for primary y-axis
    ax1.grid(axis='y', linestyle='-', color='gray', zorder=1)

    # Secondary y-axis for memory usage
    ax2 = ax1.twinx()
    ax2.plot(algorithms, avg_memories, color='red', marker='o', linestyle='solid', linewidth=2, zorder=3, label='Memory Usage')
    ax2.set_ylabel('Memory Usage (MB)', color='red')
    ax2.tick_params(axis='y', labelcolor='red')

    # Use the same grid lines for the secondary y-axis
    ax2.grid(False)  # Disable separate grid for ax2

    ax1.legend(loc='upper left')  # Legend for the bar chart
    ax2.legend(loc='upper right')  # Legend for the line plot

    plt.title('Execution Time and Memory Usage of Hashing One Password')
    plt.show()

# run_time()
times_and_plot()