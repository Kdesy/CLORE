from utils import *
import time
import copy
import math

# Comparison algorithm
def compare(m, p, CLs, CRs):   
    CR_m = copy.deepcopy(CRs[m])
    CR_m.pop(0)   
    CR_p = copy.deepcopy(CRs[p])
    CR_p.pop(0)
    CL_p = CLs[p]

    run_time = 0.0
    res = 0

    for i in range(0, n):
        knode_i = CL_p[i][0]
        up_i = CL_p[i][1]
        data_bytes = str(knode_i + N).encode('utf-8')
        start_time = time.time()
        rand_i = H(data_bytes)
        um_i = (CR_m[i] - rand_i) % M
        if um_i == (up_i + 1) % M:
            res = 1
            run_time += time.time() - start_time
            break
        if up_i == (um_i + 1) % M:
            res = -1
            run_time += time.time() - start_time
            break
        run_time += time.time() - start_time
    return res, run_time, i + 1

# Right encryption algorithm
def right_encrypt(num, n):
    CR = []
    CR.append(N)
    start_time = time.time()
    for i in range(1, n + 1):
        pre, pre_ = prefix(num, i - 1, n)  
        u_i = (aes(K, (i, pre_)) + get_ith(num, i, n)) % M
        knode_i = aes(K, pre)
        data_bytes = str(knode_i + N).encode('utf-8')
        rand_i = H(data_bytes)
        r_i = (u_i + rand_i) % M
        CR.append(r_i)
    end_time = time.time()
    return CR, end_time - start_time

# Left encryption algorithm
def left_encrypt(num, n):
    CL = []
    start_time = time.time()
    for i in range(1, n + 1):
        pre, pre_ = prefix(num, i - 1, n)
        mask_i = aes(K, (i, pre_))
        up_i = (mask_i + get_ith(num, i, n)) % M
        knode_i = aes(K, pre)
        l_i = (knode_i, up_i)
        CL.append(l_i)
    end_time = time.time()
    return CL, end_time - start_time

# Ciphertext length
def ciphertext_bytes(n):
    return N_BYTES + math.ceil(n * 2 / 8)

# Test
file_name = "test_clore"

record = [[[0, 0, 0, 0, 0, 0, 0, 0] for _ in range(len(ns))] for _ in range(2)]

for choose in range(0, 2):
    for idx, n in enumerate(ns):
        for _ in range(iters):
            # Data sampling
            nums = sample_nums(n, nums_number, choose=choose)
            m, p = nums[0], nums[1]

            # Encrypt and record the time
            CR_m, right_encryption_time = right_encrypt(m, n)
            record[choose][idx][0] += right_encryption_time
            record[choose][idx][1] += 1
            CL_m, left_encryption_time = left_encrypt(m, n)
            record[choose][idx][2] += left_encryption_time
            record[choose][idx][3] += 1
            CR_p, right_encryption_time = right_encrypt(p, n)
            record[choose][idx][0] += right_encryption_time
            record[choose][idx][1] += 1
            CL_p, left_encryption_time = left_encrypt(p, n)
            record[choose][idx][2] += left_encryption_time
            record[choose][idx][3] += 1

            # Randomly select two elements for comparison
            res, comp_time, comp_fre = compare(0, 1, [CL_m, CL_p], [CR_m, CR_p])
            record[choose][idx][4] += comp_time
            record[choose][idx][5] += 1
            record[choose][idx][6] += comp_fre
            record[choose][idx][7] += 1

        with open(f"{file_name}_{choose}.txt", 'a', encoding='utf-8') as f:
            f.write(f"plaintext_bits(n): {n}, right_encryption_avg_time: {record[choose][idx][0] / record[choose][idx][1] * 1e6 if record[choose][idx][1] > 0 else 0} us，left_encryption_avg_time: {record[choose][idx][2] / record[choose][idx][3] * 1e6 if record[choose][idx][3] > 0 else 0} us，comparison_avg_time: {record[choose][idx][4] / record[choose][idx][5] * 1e6 if record[choose][idx][5] > 0 else 0} us，comparison_avg_bits: {record[choose][idx][6] / record[choose][idx][7]}, ciphertext_bytes: {ciphertext_bytes(n)}\n")