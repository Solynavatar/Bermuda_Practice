import hashlib
import random
from phe import paillier

def rerandomize(public_key, ciphertext):
    """
    手动重新随机化 Paillier 密文
    ciphertext: EncryptedNumber
    """
    n = public_key.n
    nsquare = n * n
    s = random.SystemRandom().randrange(1, n)
    new_c = (ciphertext.ciphertext() * pow(s, n, nsquare)) % nsquare
    return paillier.EncryptedNumber(public_key, new_c, ciphertext.exponent)


# ========== 公共参数 ==========
p = 208351617316091241234326746312124448251235562226470491514186331217050270460481

def H(u):
    return int(hashlib.sha256(u.encode()).hexdigest(), 16) % p

# ========== P2 生成 Paillier 同态加密密钥对 ==========
public_key, private_key = paillier.generate_paillier_keypair()

# ========== 双方私钥 ==========
k1 = random.randint(1, p-1)
k2 = random.randint(1, p-1)

# ========== 输入 ==========
P1_V = ['alice', 'bob', 'carol']
P2_W = [('bob', 114), ('dave', 514), ('carol', 1919), ('eve', 180)]

print("P1 集合:", P1_V)
print("P2 集合:", P2_W)

# ========== Round 1: P1 ==========
P1_V_hash_k1 = [pow(H(v), k1, p) for v in P1_V]

print("P1 发送给 P2:", P1_V_hash_k1)

# ========== Round 2: P2 ==========
Z = [pow(item, k2, p) for item in P1_V_hash_k1]
P2_W_hash_k2_enc = []
for wj, tj in P2_W:
    hj_k2 = pow(H(wj), k2, p)
    enc_tj = public_key.encrypt(tj)
    P2_W_hash_k2_enc.append( (hj_k2, enc_tj) )

# ========== Round 3: P1 ==========
intersection_ciphertexts = []
for hj_k2, enc_tj in P2_W_hash_k2_enc:
    hj_k1k2 = pow(hj_k2, k1, p)
    if hj_k1k2 in Z:
        intersection_ciphertexts.append(enc_tj)

# 同态求和
if intersection_ciphertexts:
    sum_cipher = intersection_ciphertexts[0]
    for ct in intersection_ciphertexts[1:]:
        sum_cipher += ct
else:
    sum_cipher = public_key.encrypt(0)

# 随机化密文
sum_cipher = rerandomize(public_key, sum_cipher)

# ========== P2 解密 ==========
intersection_sum = private_key.decrypt(sum_cipher)

print("最终交集 t_j 值之和:", intersection_sum)
