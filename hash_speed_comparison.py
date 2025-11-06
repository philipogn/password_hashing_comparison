from abc import ABC, abstractmethod
import hashlib, bcrypt, scrypt, psutil, time
from argon2 import PasswordHasher
import matplotlib.pyplot as plt

class HashAlgorithm(ABC):
    ''' Abstract base class for hasing algorithms'''
    @abstractmethod
    def hash(self, password: str):
        self.password = password

class Argon2Hash(HashAlgorithm):
    name = 'Argon2'
    def hash(self, password: str):
        ph = PasswordHasher(time_cost=1, memory_cost=47104, parallelism=1)  # Higher time and memory cost, parallelism
        for word in password:
            ph.hash(word)

class BcryptHash(HashAlgorithm):
    name = 'Bcrypt'
    def hash(self, password: str):
        for word in password:
            bcrypt.hashpw(word.encode(), bcrypt.gensalt(rounds=9))  # Adjusted rounds

class ScryptHash(HashAlgorithm):
    name = 'Scrypt'
    def hash(self, password: str):
        for word in password:
            scrypt.hash(word, b'salt', N=2**17, r=8, p=1)

class PBKDF2Hash(HashAlgorithm):
    name = 'PBKDF2'
    def hash(self, password):
        for word in password:
            hashlib.pbkdf2_hmac('sha256', word.encode(), b'salt', 600000)  # Adjusted iterations




class Benchmark():
    def __init__(self, algorithm: list, password: str, runs: int=100):
        self.algorithm = algorithm
        self.password = password
        self.runs = runs
        self.results = {}
    
    # Measure execution time
    def measure_time(self, hash_func):
        start_time = time.perf_counter()
        hash_func(self.password)
        return time.perf_counter() - start_time

    # Run the test multiple times and average the results
    def run(self):
        process = psutil.Process()
        for algo in self.algorithm:
            times, memory_usages = [], []
            for _ in range(self.runs):
                memory_before = process.memory_info().rss / (1024 * 1024)  # Convert to MB
                exec_time = self.measure_time(algo.hash)
                memory_after = process.memory_info().rss / (1024 * 1024)  # Convert to MB
                memory_usage = memory_after
                times.append(exec_time)
                memory_usages.append(memory_usage)

            avg_time = sum(times) / len(times)
            avg_mem = sum(memory_usages) / len(memory_usages)
            print(f'{algo.name} - Avg time: {avg_time:.4f} seconds, Avg mem: {avg_mem:.2f} MB')
            self.results[algo.name] = {
                'time': avg_time,
                'memory': avg_mem
            }


    def plot(self):
        names = list(self.results.keys())
        times = [self.results[n]["time"] for n in names]
        memories = [self.results[n]["memory"] for n in names]

        fig, ax1 = plt.subplots(figsize=(10,6))
        ax1.bar(names, times, color='skyblue', label='Execution Time')
        ax1.set_xlabel('Hashing Algorithms')
        ax1.set_ylabel('Execution Time (s)', color='blue')
        ax1.grid(axis='y', linestyle='-', color='gray', zorder=1)
        ax1.tick_params(axis='y', labelcolor='blue')
        #check

        ax2 = ax1.twinx()
        ax2.plot(names, memories, color='red', marker='o', linestyle='solid', linewidth=2, zorder=3, label='Memory Usage')
        ax2.set_ylabel('Memory Usage (MB)', color='red')
        ax2.tick_params(axis='y', labelcolor='red')
        ax2.grid(False)  # Disable separate grid for ax2

        ax1.legend(loc='upper left')  # Legend for the bar chart
        ax2.legend(loc='upper right')  # Legend for the line plot
        plt.title(f'Execution Time and Memory Usage of Hashing {len(self.password)} Password')
        plt.show()


if __name__ == '__main__':
    PASSWORD_LIST = open('password-list-top-100.txt').read().splitlines()
    PASSWORD = "password1234!"
    
    algos = [Argon2Hash(), BcryptHash(), ScryptHash(), PBKDF2Hash()]
    bench = Benchmark(algos, PASSWORD, runs=100)
    bench.run()
    bench.plot()