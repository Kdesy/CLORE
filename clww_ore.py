from utils import *
import time
import math

# Encryption algorithm
def encrypt(num, n):
    C = []
    start_time = time.time()
    for i in range(1, n + 1):
        _, pre_ = prefix(num, i - 1, n)
        u_i = (aes(K, (i, pre_)) + get_ith(num, i, n)) % M
        C.append(u_i)
    end_time = time.time()
    return C, end_time - start_time

# Comparison algorithm
def compare(c_m: np.ndarray, c_p: np.ndarray):
    res = 0
    start_time = time.time()
    for i in range(len(c_m)):
        if c_m[i] == (c_p[i] + 1) % M:
            res = 1
            break
        if c_p[i] == (c_m[i] + 1) % M:
            res = -1
            break
    end_time = time.time()
    return res, end_time - start_time

# Ciphertext length
def ore_ciphertext_bytes(n):
    return math.ceil(n * 2 / 8)

# Test
file_name = "test_clww_ore"

record = [[[0, 0, 0, 0] for _ in range(len(ns))] for _ in range(2)]

for choose in range(0, 2):
    for idx, n in enumerate(ns):
        for _ in range(iters):
            # Data sampling
            nums = sample_nums(n, nums_number, choose=choose)

            # Encrypt and record the time
            Cs = []
            for num in nums:
                C, encrypt_time = encrypt(num, n)
                Cs.append(C)
                record[choose][idx][0] += encrypt_time
                record[choose][idx][1] += 1
            Cs = np.array(Cs)
            
            # Randomly select two elements for comparison
            i, j = get_comp_pair(len(nums))
            res, comp_time = compare(Cs[i], Cs[j])
            record[choose][idx][2] += comp_time
            record[choose][idx][3] += 1

        with open(f"{file_name}_{choose}.txt", 'a', encoding='utf-8') as f:
            f.write(f"plaintext_bits(n): {n}, encryption_avg_time: {record[choose][idx][0] / record[choose][idx][1] * 1e6 if record[choose][idx][1] > 0 else 0} us, comparison_avg_time: {record[choose][idx][2] / record[choose][idx][3] * 1e6 if record[choose][idx][3] > 0 else 0} us, ciphertext_bytes: {ore_ciphertext_bytes(n)}\n")