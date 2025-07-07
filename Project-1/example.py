# example.py
from sm4 import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc
import os

key = b'0123456789abcdeF'   # 16 字节密钥
iv = os.urandom(16)         # CBC 模式随机向量

data = b'Hello, this is a test message for SM4 made by Bermuda Warehouse DC. Everything is for atonement.'

# ECB 模式
enc = encrypt_ecb(key, data)
dec = decrypt_ecb(key, enc)
print('ECB 解密结果：', dec)

# CBC 模式
enc2 = encrypt_cbc(key, data, iv)
dec2 = decrypt_cbc(key, enc2, iv)
print('CBC 解密结果：', dec2)
