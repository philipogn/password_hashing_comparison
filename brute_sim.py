import hashlib
import bcrypt
import scrypt
from argon2 import PasswordHasher, exceptions
import time
import psutil
import matplotlib.pyplot as plt

# Known password to brute-force
known_passwords = ["trustno1", "qwertyuiop", "112233", "1qaz2wsx", "159753"]

ph = PasswordHasher(time_cost=1, memory_cost=47104, parallelism=1)

# Dictionary attack function
def dictionary_attack(target_hash, verify_func):
    with open('password-list-top-100.txt') as file:
        for password in file:
            password = password.strip()
            if verify_func(password, target_hash):
                return password  # Found match
    return None  # No match found

# Verification functions
def argon2_verify(password, target_hash):
    try:
        return ph.verify(target_hash, password)
    except exceptions.VerifyMismatchError:
        return False

def bcrypt_verify(password, target_hash):
    return bcrypt.checkpw(password.encode(), target_hash)

def scrypt_verify(password, target_hash):
    hashed_attempt = scrypt.hash(password, b'salt', N=2**17, r=8, p=1)  # Match parameters used in target hash
    return hashed_attempt == target_hash

def pbkdf2_verify(password, target_hash):
    hashed_attempt = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 600000)
    return hashed_attempt == target_hash

# Simulate brute-force for each password and hashing algorithm
def brute_force_all(password_list):
    total_time = {"Argon2": 0, "bcrypt": 0, "scrypt": 0, "PBKDF2": 0}
    results = []

    for password in password_list:
        # Compute target hashes for the current password
        target_hash_argon2 = ph.hash(password)
        target_hash_bcrypt = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=9))
        target_hash_scrypt = scrypt.hash(password, b'salt', N=2**17, r=8, p=1)
        target_hash_pbkdf2 = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 600000)
        
        # Test each algorithm
        for algorithm, target_hash, verify_func in [
            ("Argon2", target_hash_argon2, argon2_verify),
            ("bcrypt", target_hash_bcrypt, bcrypt_verify),
            ("scrypt", target_hash_scrypt, scrypt_verify),
            ("PBKDF2", target_hash_pbkdf2, pbkdf2_verify)
            
        ]:
            start_time = time.perf_counter()
            result = dictionary_attack(target_hash, verify_func)
            memory_usage = psutil.Process().memory_info().rss / (1024 * 1024)  # convert to MB
            end_time = time.perf_counter()

            # Accumulate total time for the algorithm
            total_time[algorithm] += end_time - start_time

            # Store results
            results.append({
                "Password": password,
                "Algorithm": algorithm,
                "Found": result if result else "Not found",
                "Time (s)": f"{end_time - start_time:.4f}",
                "Memory (MB)": f"{memory_usage:.2f}"
            })

    return results, total_time

# Run the brute-force simulation
results, total_time = brute_force_all(known_passwords)

# # Print results
# for result in results:
#     print(f"Password: {result['Password']} | Algorithm: {result['Algorithm']} | "
#           f"Found: {result['Found']} | Time: {result['Time (s)']} seconds | "
#           f"Memory: {result['Memory (MB)']} MB")

# Print total time per algorithm
print("\nTotal Time per Algorithm:")
for algorithm, time_taken in total_time.items():
    print(f"{algorithm}: {time_taken:.4f} seconds")

algorithms = list(total_time.keys())
times = list(total_time.values())

# Create a bar chart
plt.figure(figsize=(8, 6))
plt.bar(algorithms, times, zorder=3)
plt.grid(axis='y', zorder=0)

# Add labels and title
plt.xlabel('Hashing Algorithm')
plt.ylabel('Total Time (seconds)')
plt.title('Total Time Taken for Dictionary Attack to Crack Algorithms')

# Display the bar chart
plt.show()