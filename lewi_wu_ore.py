from utils import *
import os
import hashlib
import random
import math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Define a PRF
def prf_aes(key: bytes, data: bytes) -> bytes:  
    iv = os.urandom(16)  
    padder = padding.PKCS7(128).padder() 
    padded_data = padder.update(data) + padder.finalize()  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  

# Calculate the hash value
def H(data: bytes) -> int:
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, 'big') % 3

# CMP
def cmp(a: int, b: int) -> int:
    return (a > b) - (a < b)

# Small domain scheme
class SmallDomainORE:

    def setup(self, security_param: int, domain_size_N: int):        
        k = os.urandom(security_param // 8)       
        pi_list = list(range(domain_size_N))
        random.shuffle(pi_list)
        pi = {i: pi_list[i] for i in range(domain_size_N)}  
        secret_key = {'k': k, 'pi': pi}
        return secret_key

    # Left encryption algorithm
    def left_encrypt(self, sk: dict, m: int):
        k, pi = sk['k'], sk['pi']     
        CL_part = prf_aes(k, pi[m].to_bytes(8, 'big'))      
        CL = {'k_prime': CL_part, 'h': pi[m]}
        return CL

    # Right encryption algorithm
    def right_encrypt(self, sk: dict, m: int):
        k, pi = sk['k'], sk['pi']
        domain_size_N = len(pi)      
        pi_inverse_list = {v: k for k, v in pi.items()}       
        r = os.urandom(16)       
        v = []
        for i in range(domain_size_N):            
            apple = prf_aes(k, i.to_bytes(8, 'big'))
            vi_part_ = H(apple + r)
            vi_part = cmp(pi_inverse_list[i], m)           
            vi = (vi_part + vi_part_) % 3
            v.append(vi)           
        CR = {'r': r, 'v': v}
        return CR

    # Comparison algorithm
    def compare(self, CL: dict, CR: dict) -> int:
        k_prime, h = CL['k_prime'], CL['h']
        r, v = CR['r'], CR['v'] 
        orange = H(k_prime + r)
        res = (v[h] - orange) % 3
        if res == 2:
            return -1
        return res

# Large domain scheme
class LargeDomainORE:

    def __init__(self, block_bits: int, total_bits: int):
        self.d = 2**block_bits  
        self.n = math.ceil(total_bits / block_bits) 
        self.total_bits = total_bits
        self.block_bits = block_bits

    def _to_base_d(self, m: int):
        if m >= 2**self.total_bits:
            raise ValueError(f"The message {m} is beyond the range of {self.total_bits}-bit")      
        res = []
        temp_m = m
        for _ in range(self.n):
            res.append(temp_m % self.d)
            temp_m //= self.d
        return list(reversed(res))

    # Generate pseudo-random permutations
    def _get_prp(self, key: bytes, domain_size: int):
        pi_list = list(range(domain_size))
        random.Random(key).shuffle(pi_list)
        pi = {i: pi_list[i] for i in range(domain_size)}
        pi_inverse = {v: k for k, v in pi.items()}
        return pi, pi_inverse
        
    def setup(self, security_param: int):
        key_bytes = security_param // 8
        k1 = secrets.token_bytes(key_bytes)
        k2 = secrets.token_bytes(key_bytes)
        return {'k1': k1, 'k2': k2}

    # Left encryption algorithm
    def left_encrypt(self, sk: dict, m: int):
        start_time = time.time()
        k1, k2 = sk['k1'], sk['k2']
        m_based_d = self._to_base_d(m)    
        CL = []
        prefix = b''
        for i in range(self.n):
            prp_key = prf_aes(k2, prefix)
            pi, _ = self._get_prp(prp_key, self.d)   
            banana = pi[m_based_d[i]]
            prf_output = prf_aes(k1, prefix + banana.to_bytes(2, 'big'))       
            u_i = {'k_prime': prf_output, 'h': banana}
            CL.append(u_i)
            prefix += m_based_d[i].to_bytes(2, 'big')           
        return CL, time.time() - start_time

    # Right encryption algorithm
    def right_encrypt(self, sk: dict, m: int):
        start_time = time.time()
        k1, k2 = sk['k1'], sk['k2']
        m_based_d = self._to_base_d(m)        
        r = os.urandom(16)
        CR_v = []
        prefix = b''        
        for i in range(self.n):
            v_i = []
            prp_key = prf_aes(k2, prefix)
            _, pi_inverse = self._get_prp(prp_key, self.d)
            for j in range(self.d):
                j_star = pi_inverse[j]           
                grape = prf_aes(k1, prefix + j.to_bytes(2, 'big'))             
                h_output = H(grape + r)
                cmp_val = cmp(j_star, m_based_d[i])              
                z_ij = (cmp_val + h_output) % 3
                v_i.append(z_ij)           
            CR_v.append(v_i)
            prefix += m_based_d[i].to_bytes(2, 'big')  
        CR = {'r': r, 'v': CR_v}         
        return CR, time.time() - start_time

    # Comparison algorithm
    def compare(self, ct_left: list, CR: dict) -> int:
        start_time = time.time()
        r, v = CR['r'], CR['v']      
        for i in range(self.n):
            k_prime_i, h_i = ct_left[i]['k_prime'], ct_left[i]['h']
            v_i = v[i]           
            h_output = H(k_prime_i + r)          
            res = (v_i[h_i] - h_output) % 3          
            if res != 0:
                if res == 2:
                    return -1, time.time() - start_time
                return res, time.time() - start_time        
        return 0, time.time() - start_time 
    
# Ciphertext length
def left_bytes(n, block_bits):
    return (len(DEFAULT_KEY) + math.ceil(n / 8)) * math.ceil(n / block_bits)

def right_bytes(n, block_bits):
    return len(DEFAULT_KEY) + (math.ceil(2 ** block_bits / 8) * math.ceil(n / block_bits)) * 2

# Test
for block_bits in [4, 8, 12]:
        
        file_name = "test_lewi_wu_ore"

        record = [[[0, 0, 0, 0, 0, 0] for _ in range(len(ns))] for _ in range(2)]

        for choose in range(0, 2):
            for idx, n in enumerate(ns):
                large_ore = LargeDomainORE(block_bits=block_bits, total_bits=n)
                sk_large = large_ore.setup(security_param=128)

                for _ in range(iters):
                    # Data sampling
                    nums = sample_nums(n, nums_number, choose=choose)

                    # Encrypt and record the time
                    CLs = []
                    CRs = []
                    for num in nums:
                        CL, left_encrypt_time = large_ore.left_encrypt(sk_large, num)
                        CR, right_encrypt_time = large_ore.right_encrypt(sk_large, num)

                        record[choose][idx][0] += right_encrypt_time
                        record[choose][idx][1] += 1
                        record[choose][idx][2] += left_encrypt_time
                        record[choose][idx][3] += 1
                        CLs.append(CL)
                        CRs.append(CR)

                    # Randomly select two elements for comparison
                    m, p = 0, 1
                    res, comp_time = large_ore.compare(CLs[m], CRs[p])
                    record[choose][idx][4] += comp_time
                    record[choose][idx][5] += 1

                with open(f"{file_name}_{block_bits}_{choose}.txt", 'a', encoding='utf-8') as f:
                    f.write(f"plaintext_bits(n): {n}, right_encryption_avg_time: {record[choose][idx][0] / record[choose][idx][1] * 1e6 if record[choose][idx][1] > 0 else 0} us, left_encryption_avg_time: {record[choose][idx][2] / record[choose][idx][3] * 1e6 if record[choose][idx][3] > 0 else 0} us, comparison_avg_time: {record[choose][idx][4] / record[choose][idx][5] * 1e6 if record[choose][idx][5] > 0 else 0} us, ciphertext_bytes: {right_bytes(n, block_bits)}\n")