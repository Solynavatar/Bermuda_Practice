import random
import time

# 定义 SM2 推荐曲线参数
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx= 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy= 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (Gx, Gy)

# 椭圆曲线上的点加法
def point_add(P, Q):
    if P == (0,0): return Q
    if Q == (0,0): return P
    if P == Q:
        lam = (3*P[0]*P[0] + a) * pow(2*P[1], -1, p) % p
    else:
        lam = (Q[1]-P[1]) * pow(Q[0]-P[0], -1, p) % p
    x = (lam*lam - P[0] - Q[0]) % p
    y = (lam*(P[0]-x) - P[1]) % p
    return (x, y)

# 点乘 k*P（最简单版本，二进制展开法）
def scalar_mult(k, P):
    R = (0,0)
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_add(P, P)
        k >>=1
    return R

# 简单 hash，用 Python 内置 hash 代替
def simple_hash(m):
    return hash(m) & ((1<<256)-1)

# 预计算 G 的倍数
precomputed_G = [scalar_mult(i, G) for i in range(1, 17)]

def scalar_mult_optimized(k, P):
    # 简单 4位窗口
    R = (0,0)
    k_bin = bin(k)[2:]
    i = 0
    while i < len(k_bin):
        if k_bin[i] == '0':
            R = point_add(R, R)
            i += 1
        else:
            width = min(4, len(k_bin)-i)
            while width>1 and k_bin[i:i+width][0]=='0':
                width -=1
            digit = int(k_bin[i:i+width],2)
            R = point_add(R, precomputed_G[digit-1])
            for _ in range(width):
                R = point_add(R, R)
            i += width
    return R

def sm2_encrypt_optimized(M, P):
    k = random.randrange(1, n)
    C1 = scalar_mult_optimized(k, G)
    S = scalar_mult(k, P)
    x2, y2 = S
    t = simple_hash(str(x2)+str(y2))
    C2 = M ^ t
    return (C1, C2)

# 测试
M = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
private_key = random.randrange(1, n)
public_key = scalar_mult(private_key, G)

start = time.time()
cipher_opt = sm2_encrypt_optimized(M, public_key)
end = time.time()

print("优化版SM2加密结果:", cipher_opt)
print(f"用时: {(end-start)*1000:.2f} ms")
