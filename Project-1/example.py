# example.py
from sm4 import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc, encrypt_ctr, decrypt_ctr, encrypt_cfb, decrypt_cfb, encrypt_ofb, decrypt_ofb
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

# CTR 模式
enc3 = encrypt_ctr(key, data, iv)
dec3 = decrypt_ctr(key, enc3, iv)
print('CTR 解密结果：', dec3)

# CFB 模式
enc4 = encrypt_cfb(key, data, iv)
dec4 = decrypt_cfb(key, enc4, iv)
print('CFB 解密结果：', dec4)

# OFB 模式
enc5 = encrypt_ofb(key, data, iv)
dec5 = decrypt_ofb(key, enc5, iv)
print('OFB 解密结果：', dec5)