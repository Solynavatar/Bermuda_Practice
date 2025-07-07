# sm4.py

import struct
from copy import deepcopy

# 常量参数
SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]

def _rotl(x, n):
    # _rotl 是循环左移函数，用于对 32 位整数左移 n 位
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def _tau(a):
    # _tau 是非线性变换，使用 SBOX 对输入的每个字节进行替换
    return struct.unpack('>I', bytes(SBOX[b] for b in struct.pack('>I', a)))[0]

def _l(b):
    # _l 是线性变换函数，用于加密过程中的扩散效果
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)

def _l_prime(b):
    # _l_prime 是线性变换函数，用于密钥扩展阶段
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)

def _key_expansion(key):
    # 根据密钥生成 32 个轮密钥
    MK = struct.unpack('>4I', key)
    K = [MK[i] ^ FK[i] for i in range(4)]
    for i in range(32):
        temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]
        K.append(K[i] ^ _l_prime(_tau(temp)))
    return K[4:]

def _round_func(x, rk):
    # 实现加密解密的核心轮函数
    return x[0] ^ _l(_tau(x[1] ^ x[2] ^ x[3] ^ rk))

def _crypt_block(key, block, decrypt=False):
    # 实现单个 16 字节块的加密或解密过程
    rk = _key_expansion(key)
    if decrypt:
        rk = rk[::-1]
    X = list(struct.unpack('>4I', block))
    for r in rk:
        X.append(_round_func(X[-4:], r))
    return struct.pack('>4I', X[-1], X[-2], X[-3], X[-4])

def pad(data):
    # 实现 PKCS#7 填充
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    # 移除 PKCS#7 填充
    return data[:-data[-1]]

def _split_blocks(data):
    # 将数据按 16 字节切分
    return [data[i:i+16] for i in range(0, len(data), 16)]

def encrypt_ecb(key, plaintext):
    # ECB 模式加密
    return b''.join(_crypt_block(key, blk) for blk in _split_blocks(pad(plaintext)))

def decrypt_ecb(key, ciphertext):
    # ECB 模式解密
    decrypted = b''.join(_crypt_block(key, blk, decrypt=True) for blk in _split_blocks(ciphertext))
    return unpad(decrypted)

def encrypt_cbc(key, plaintext, iv):
    # CBC 模式加密
    plaintext = pad(plaintext)
    res, prev = [], iv
    for blk in _split_blocks(plaintext):
        blk_xor = bytes(a ^ b for a, b in zip(blk, prev))
        enc = _crypt_block(key, blk_xor)
        res.append(enc)
        prev = enc
    return b''.join(res)

def decrypt_cbc(key, ciphertext, iv):
    # CBC 模式解密
    res, prev = [], iv
    for blk in _split_blocks(ciphertext):
        dec = _crypt_block(key, blk, decrypt=True)
        res.append(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = blk
    return unpad(b''.join(res))

def encrypt_ctr(key, plaintext, iv):
    # CTR模式加密/解密，流式加密，不使用填充
    res, counter = [], int.from_bytes(iv, 'big')
    length = len(plaintext)
    offset = 0
    while offset < length:
        blk = plaintext[offset:offset+16]
        keystream = _crypt_block(key, counter.to_bytes(16, 'big'))
        counter += 1
        # 只异或当前块长度，避免多余字节
        res.append(bytes(a ^ b for a, b in zip(blk, keystream[:len(blk)])))
        offset += 16
    return b''.join(res)

def decrypt_ctr(key, ciphertext, iv):
    # CTR解密和加密相同
    return encrypt_ctr(key, ciphertext, iv)

def encrypt_ofb(key, plaintext, iv):
    # OFB模式加密，流式加密，不使用填充
    res, output = [], iv
    length = len(plaintext)
    offset = 0
    while offset < length:
        blk = plaintext[offset:offset+16]
        output = _crypt_block(key, output)
        # 只异或当前块长度，避免多余字节
        res.append(bytes(a ^ b for a, b in zip(blk, output[:len(blk)])))
        offset += 16
    return b''.join(res)

def decrypt_ofb(key, ciphertext, iv):
    # OFB解密和加密相同
    return encrypt_ofb(key, ciphertext, iv)


def encrypt_cfb(key, plaintext, iv):
    # CFB 模式加密：每次加密前一个密文块或 IV，然后和明文异或
    plaintext = pad(plaintext)
    res, prev = [], iv
    for blk in _split_blocks(plaintext):
        output = _crypt_block(key, prev)
        enc = bytes(a ^ b for a, b in zip(blk, output))
        res.append(enc)
        prev = enc
    return b''.join(res)

def decrypt_cfb(key, ciphertext, iv):
    # CFB 模式解密：加密前一个密文块或 IV，然后和密文异或得到明文
    res, prev = [], iv
    for blk in _split_blocks(ciphertext):
        output = _crypt_block(key, prev)
        dec = bytes(a ^ b for a, b in zip(blk, output))
        res.append(dec)
        prev = blk
    return unpad(b''.join(res))
