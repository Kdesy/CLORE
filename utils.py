from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import numpy as np
import random
import secrets
import hashlib

M = 3 
iters = 100000    # Set the number of tests
N = secrets.randbelow(2**128)    # Simulate random number selection for test 
N_BYTES = 16 
nums_number = 2

ns = [8, 16, 32, 48, 64, 96, 128]

# Generate random numbers from normal distribution 
def secure_normal_numpy(mu=0.0, sigma=1.0, size=None):
    seed = secrets.randbits(128)
    rng = np.random.Generator(np.random.PCG64(seed))
    return rng.normal(mu, sigma, size)

# Uniform distribution sampling and normal distribution sampling
def sample_nums(n, nums_number, choose=0):
    nums = []
    if choose == 0:
        for _ in range(nums_number):
            nums.append(secrets.randbelow(2 ** n))
    elif choose == 1:
        for _ in range(nums_number):
            nums.append(int(secure_normal_numpy(mu=2 ** (n - 1), sigma=2 ** n / 12)))
    if choose == 2:
        for _ in range(nums_number):
            nums.append(random.randint(0, 2 ** n - 1))
    return nums

# Calculate the prefix
def prefix(num, i, n):
    binary_str = bin(num)[2:]
    binary_str = binary_str.zfill(n)     
    if i > len(binary_str):
        high_bits = binary_str
    else:
        high_bits = binary_str[:i]   
    remaining_bits = n - len(high_bits)
    result_binary = high_bits + '0' * remaining_bits 
    if high_bits == '':
        high_bits = '0'
    return int(high_bits, 2), int(result_binary, 2)

# Calculate the hash value
def H(data: bytes) -> int:
    if not isinstance(data, bytes):
        raise TypeError("The input of the hash function H must be a byte string.")
    hasher = hashlib.sha256(data)
    digest_bytes = hasher.digest()
    return int.from_bytes(digest_bytes, 'big')

# Obtain the i-th element
def get_ith(num, i, n):
    binary_str = bin(num)[2:]
    binary_str = binary_str.zfill(n) 
    if i > len(binary_str):
        return 0
    return int(binary_str[i - 1])

# Obtain two random index
def get_comp_pair(nums_number):
    i = random.randint(0, nums_number - 1)
    j = random.randint(0, nums_number - 1)
    while i == j:
        j = random.randint(0, nums_number - 1)
    return i, j

# Define a default AES key
DEFAULT_KEY = b'my_secret_key123' 

# Generate a random AES key
def get_key():   
    return secrets.token_bytes(16) 

# Obtain the AES key
K = get_key()

# AES encryption 
def aes(k, u_i):
    cipher = AES.new(k, AES.MODE_ECB)
    u_i_bytes = str(u_i).encode('utf-8')  
    padded_data = pad(u_i_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return int.from_bytes(encrypted_data, byteorder='big')