import hashlib
import bcrypt
import scrypt
from argon2 import PasswordHasher, exceptions
import time
import itertools

# Known password to brute-force
known_password = "ab"
candidate_chars = "abcdefghijklmnopqrstuvwxyz0123456789"  # Character set for brute-force
max_length = 4  # Maximum password length to try

# Hash each password for each algorithm
# ph = PasswordHasher()
ph = PasswordHasher(time_cost=3, memory_cost=4096, parallelism=1)  # Adjusted parameters

target_hash_argon2 = ph.hash(known_password)
target_hash_bcrypt = bcrypt.hashpw(known_password.encode(), bcrypt.gensalt(rounds=12)) #bcrypt.hashpw(known_password.encode(), bcrypt.gensalt())
target_hash_pbkdf2 = hashlib.pbkdf2_hmac('sha256', known_password.encode(), b'salt', 200000) #hashlib.pbkdf2_hmac('sha256', known_password.encode(), b'salt', 100000)
target_hash_scrypt = scrypt.hash(known_password, b'salt', N=2**14, r=8, p=1) #scrypt.hash(known_password, b'salt')

def brute_force(algorithm, target_hash, verify_func):
    # Generate candidate passwords
    for length in range(1, max_length + 1):
        for candidate in itertools.product(candidate_chars, repeat=length):
            attempt = ''.join(candidate)
            if verify_func(attempt, target_hash):
                return attempt  # Found match
    return None  # No match found

# Verification functions
def argon2_verify(password, target_hash):
    try:
        return ph.verify(target_hash, password)
    except exceptions.VerifyMismatchError:
        return False

def bcrypt_verify(password, target_hash):
    return bcrypt.checkpw(password.encode(), target_hash)

def pbkdf2_verify(password, target_hash):
    hashed_attempt = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 200000)
    return hashed_attempt == target_hash

def scrypt_verify(password, target_hash):
    hashed_attempt = scrypt.hash(password, b'salt')
    return hashed_attempt == target_hash

# Simulate brute-force for each hashing algorithm
def brute_force_all():
    for algorithm, target_hash, verify_func in [
        ("Argon2", target_hash_argon2, argon2_verify),
        ("bcrypt", target_hash_bcrypt, bcrypt_verify),
        ("PBKDF2", target_hash_pbkdf2, pbkdf2_verify),
        ("scrypt", target_hash_scrypt, scrypt_verify)
    ]:
        start_time = time.perf_counter()
        result = brute_force(algorithm, target_hash, verify_func)
        memory_usage = psutil.Process().memory_info().rss / (1024 * 1024)  # convert to MB
        end_time = time.perf_counter()

        if result:
            print(f"{algorithm} - Time taken: {end_time - start_time:.4f} seconds | Max memory usage: {memory_usage:.2f} MB\n")
        else:
            print(f"No password found for {algorithm} within {max_length} character limit.\n")

brute_force_all()
