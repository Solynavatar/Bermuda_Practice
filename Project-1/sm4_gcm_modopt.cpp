#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <vector>
#include <stdexcept>
#include <algorithm>

class SM4 {
private:
    // S盒
    static const uint8_t SBOX[256];
    
    // 系统参数
    static const uint32_t FK[4];
    
    // 固定参数
    static const uint32_t CK[32];
    
    // 循环左移
    static uint32_t leftRotate(uint32_t n, uint32_t b) {
        return ((n << b) | (n >> (32 - b)));
    }
    
    // 非线性变换τ
    static uint32_t tau(uint32_t a) {
        uint8_t a_bytes[4] = {
            static_cast<uint8_t>((a >> 24) & 0xFF),
            static_cast<uint8_t>((a >> 16) & 0xFF),
            static_cast<uint8_t>((a >> 8) & 0xFF),
            static_cast<uint8_t>(a & 0xFF)
        };
        
        uint8_t b_bytes[4] = {
            SBOX[a_bytes[0]],
            SBOX[a_bytes[1]],
            SBOX[a_bytes[2]],
            SBOX[a_bytes[3]]
        };
        
        return (b_bytes[0] << 24) | 
               (b_bytes[1] << 16) | 
               (b_bytes[2] << 8) | 
               b_bytes[3];
    }
    
    // 合成变换T
    static uint32_t t(uint32_t z) {
        uint32_t b = tau(z);
        return b ^ leftRotate(b, 2) ^ 
               leftRotate(b, 10) ^ 
               leftRotate(b, 18) ^ 
               leftRotate(b, 24);
    }
    
    // 密钥扩展合成变换T'
    static uint32_t tPrime(uint32_t z) {
        uint32_t b = tau(z);
        return b ^ leftRotate(b, 13) ^ 
               leftRotate(b, 23);
    }
    
    // 轮函数F
    static uint32_t f(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
        return x0 ^ t(x1 ^ x2 ^ x3 ^ rk);
    }
    
    // 密钥扩展
    static std::vector<uint32_t> keyExpansion(const uint8_t key[16]) {
        // 将密钥分成4个32位字 (大端序)
        uint32_t mk[4];
        for (int i = 0; i < 4; i++) {
            mk[i] = (key[i*4] << 24) | 
                    (key[i*4+1] << 16) | 
                    (key[i*4+2] << 8) | 
                    key[i*4+3];
        }
        
        // 初始化轮密钥
        std::vector<uint32_t> k(36, 0);
        
        // 初始密钥加系统参数
        for (int i = 0; i < 4; i++) {
            k[i] = mk[i] ^ FK[i];
        }
        
        // 生成轮密钥
        for (int i = 0; i < 32; i++) {
            k[i+4] = k[i] ^ tPrime(k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i]);
        }
        
        // 返回32个轮密钥
        return std::vector<uint32_t>(k.begin() + 4, k.begin() + 36);
    }
    
public:
    // 加密
    static void encrypt(const uint8_t in[16], uint8_t out[16], const uint8_t key[16]) {
        // 密钥扩展
        std::vector<uint32_t> rk = keyExpansion(key);
        
        // 将输入分成4个32位字 (大端序)
        uint32_t x[36];
        for (int i = 0; i < 4; i++) {
            x[i] = (in[i*4] << 24) | 
                   (in[i*4+1] << 16) | 
                   (in[i*4+2] << 8) | 
                   in[i*4+3];
        }
        
        // 32轮迭代
        for (int i = 0; i < 32; i++) {
            x[i+4] = f(x[i], x[i+1], x[i+2], x[i+3], rk[i]);
        }
        
        // 最终输出 (反序)
        for (int i = 0; i < 4; i++) {
            out[i*4] = (x[35-i] >> 24) & 0xFF;
            out[i*4+1] = (x[35-i] >> 16) & 0xFF;
            out[i*4+2] = (x[35-i] >> 8) & 0xFF;
            out[i*4+3] = x[35-i] & 0xFF;
        }
    }
    
    // 解密
    static void decrypt(const uint8_t in[16], uint8_t out[16], const uint8_t key[16]) {
        // 密钥扩展
        std::vector<uint32_t> rk = keyExpansion(key);
        
        // 将输入分成4个32位字 (大端序)
        uint32_t x[36];
        for (int i = 0; i < 4; i++) {
            x[i] = (in[i*4] << 24) | 
                   (in[i*4+1] << 16) | 
                   (in[i*4+2] << 8) | 
                   in[i*4+3];
        }
        
        // 32轮迭代 (使用逆序轮密钥)
        for (int i = 0; i < 32; i++) {
            x[i+4] = f(x[i], x[i+1], x[i+2], x[i+3], rk[31-i]);
        }
        
        // 最终输出 (反序)
        for (int i = 0; i < 4; i++) {
            out[i*4] = (x[35-i] >> 24) & 0xFF;
            out[i*4+1] = (x[35-i] >> 16) & 0xFF;
            out[i*4+2] = (x[35-i] >> 8) & 0xFF;
            out[i*4+3] = x[35-i] & 0xFF;
        }
    }
    
    // 批量加密
    static void encryptBlocks(const uint8_t* in, uint8_t* out, size_t numBlocks, const uint8_t key[16]) {
        // 密钥扩展
        std::vector<uint32_t> rk = keyExpansion(key);
        
        for (size_t i = 0; i < numBlocks; i++) {
            encrypt(in + i*16, out + i*16, key);
        }
    }
    
    // 批量解密
    static void decryptBlocks(const uint8_t* in, uint8_t* out, size_t numBlocks, const uint8_t key[16]) {
        // 密钥扩展
        std::vector<uint32_t> rk = keyExpansion(key);
        
        for (size_t i = 0; i < numBlocks; i++) {
            decrypt(in + i*16, out + i*16, key);
        }
    }
    
    // 测量加密时间
    static double measureEncryptTime(const uint8_t* data, size_t dataSize, const uint8_t key[16], int iterations = 10000) {
        if (dataSize % 16 != 0) {
            std::cerr << "数据大小必须是16字节的倍数" << std::endl;
            return -1.0;
        }
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // 分配输出缓冲区
        std::vector<uint8_t> output(dataSize);
        
        // 多次迭代测量
        for (int i = 0; i < iterations; i++) {
            for (size_t j = 0; j < dataSize; j += 16) {
                encrypt(data + j, output.data() + j, key);
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end - start;
        
        return duration.count() / iterations;
    }
    
    // 测量解密时间
    static double measureDecryptTime(const uint8_t* data, size_t dataSize, const uint8_t key[16], int iterations = 10000) {
        if (dataSize % 16 != 0) {
            std::cerr << "数据大小必须是16字节的倍数" << std::endl;
            return -1.0;
        }
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // 分配输出缓冲区
        std::vector<uint8_t> output(dataSize);
        
        // 多次迭代测量
        for (int i = 0; i < iterations; i++) {
            for (size_t j = 0; j < dataSize; j += 16) {
                decrypt(data + j, output.data() + j, key);
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end - start;
        
        return duration.count() / iterations;
    }
};

// 初始化静态常量
const uint8_t SM4::SBOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

const uint32_t SM4::FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

const uint32_t SM4::CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// 辅助函数：打印十六进制数据
void printHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}


// SM4-GCM工作模式实现
class SM4_GCM {
private:
    // GF(2^128)乘法 (优化实现)
    static void gfmul(const uint8_t* x, const uint8_t* y, uint8_t* z) {
        uint8_t v[16];
        uint8_t r = 0;
        memcpy(v, y, 16);
        memset(z, 0, 16);
        
        for (int i = 0; i < 16; i++) {
            uint8_t byte = x[i];
            for (int j = 0; j < 8; j++) {
                if (byte & 0x80) {
                    for (int k = 0; k < 16; k++) {
                        z[k] ^= v[k];
                    }
                }
                
                // 记录v的最高位
                uint8_t carry = v[0] & 0x80 ? 0xE1 : 0; // 0xE1 = 11100001
                r = v[0] & 0x01 ? 0x80 : 0;
                
                // 左移v
                for (int k = 0; k < 15; k++) {
                    v[k] = (v[k] << 1) | ((v[k+1] & 0x80) >> 7);
                }
                v[15] = (v[15] << 1) | (r >> 7);
                
                // 模约简
                if (carry) {
                    v[15] ^= carry;
                }
                
                byte <<= 1;
            }
        }
    }

    // 增量计数器 (CTR模式)
    static void incrementCounter(uint8_t* counter) {
        for (int i = 15; i >= 12; i--) { // 只增加最后4字节
            if (++counter[i] != 0) break;
        }
    }

    // 计算GHASH
    static void ghash(const uint8_t* h, const uint8_t* aad, size_t aad_len,
                     const uint8_t* ciphertext, size_t ciphertext_len,
                     uint8_t* output) {
        uint8_t y[16] = {0};
        uint8_t block[16] = {0};
        
        // 处理AAD
        size_t aad_blocks = (aad_len + 15) / 16;
        for (size_t i = 0; i < aad_blocks; i++) {
            size_t block_size = (i == aad_blocks - 1) ? aad_len - i*16 : 16;
            memset(block, 0, 16);
            memcpy(block, aad + i*16, block_size);
            
            for (int j = 0; j < 16; j++) {
                y[j] ^= block[j];
            }
            gfmul(y, h, y);
        }
        
        // 处理密文
        size_t cipher_blocks = (ciphertext_len + 15) / 16;
        for (size_t i = 0; i < cipher_blocks; i++) {
            size_t block_size = (i == cipher_blocks - 1) ? ciphertext_len - i*16 : 16;
            memset(block, 0, 16);
            memcpy(block, ciphertext + i*16, block_size);
            
            for (int j = 0; j < 16; j++) {
                y[j] ^= block[j];
            }
            gfmul(y, h, y);
        }
        
        // 添加长度信息 (AAD长度 + 密文长度)
        uint64_t aad_bits = aad_len * 8;
        uint64_t cipher_bits = ciphertext_len * 8;
        
        for (int i = 0; i < 8; i++) {
            block[i] = (aad_bits >> (56 - i*8)) & 0xFF;
            block[i+8] = (cipher_bits >> (56 - i*8)) & 0xFF;
        }
        
        for (int j = 0; j < 16; j++) {
            y[j] ^= block[j];
        }
        gfmul(y, h, y);
        
        memcpy(output, y, 16);
    }
    
    // 生成初始计数器
    static void generateInitialCounter(const uint8_t* iv, size_t iv_len, 
                                      uint8_t* counter) {
        if (iv_len == 12) {
            // 标准96位IV
            memcpy(counter, iv, 12);
            counter[12] = 0;
            counter[13] = 0;
            counter[14] = 0;
            counter[15] = 1;
        } else {
            // 非标准IV长度，使用GHASH生成
            uint8_t zero_block[16] = {0};
            ghash(zero_block, iv, iv_len, nullptr, 0, counter);
        }
    }

public:
    // SM4-GCM加密
    static void encrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* plaintext, size_t plaintext_len,
                       uint8_t* ciphertext, uint8_t* tag, size_t tag_len = 16) {
        if (tag_len < 12 || tag_len > 16) {
            throw std::invalid_argument("Tag长度必须在12-16字节之间");
        }
        
        // 步骤1: 计算H = SM4(0^128)
        uint8_t zero_block[16] = {0};
        uint8_t H[16];
        SM4::encrypt(zero_block, H, key);
        
        // 步骤2: 生成初始计数器
        uint8_t counter[16];
        generateInitialCounter(iv, iv_len, counter);
        
        // 步骤3: 加密计数器用于GHASH
        uint8_t e_counter0[16];
        SM4::encrypt(counter, e_counter0, key);
        
        // 步骤4: CTR模式加密
        uint8_t current_counter[16];
        memcpy(current_counter, counter, 16);
        incrementCounter(current_counter); // 从J0+1开始
        
        size_t blocks = plaintext_len / 16;
        size_t remaining = plaintext_len % 16;
        
        // 处理完整块
        for (size_t i = 0; i < blocks; i++) {
            uint8_t e_counter[16];
            SM4::encrypt(current_counter, e_counter, key);
            
            // 与明文异或
            for (int j = 0; j < 16; j++) {
                ciphertext[i*16 + j] = plaintext[i*16 + j] ^ e_counter[j];
            }
            incrementCounter(current_counter);
        }
        
        // 处理剩余部分
        if (remaining > 0) {
            uint8_t e_counter[16];
            SM4::encrypt(current_counter, e_counter, key);
            
            for (size_t j = 0; j < remaining; j++) {
                ciphertext[blocks*16 + j] = plaintext[blocks*16 + j] ^ e_counter[j];
            }
        }
        
        // 步骤5: 计算GHASH
        uint8_t s[16];
        ghash(H, aad, aad_len, ciphertext, plaintext_len, s);
        
        // 步骤6: 计算认证标签
        for (size_t i = 0; i < tag_len; i++) {
            tag[i] = e_counter0[i] ^ s[i];
        }
    }
    
    // SM4-GCM解密
    static bool decrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* tag, size_t tag_len,
                       uint8_t* plaintext) {
        // 步骤1: 计算H = SM4(0^128)
        uint8_t zero_block[16] = {0};
        uint8_t H[16];
        SM4::encrypt(zero_block, H, key);
        
        // 步骤2: 生成初始计数器
        uint8_t counter[16];
        generateInitialCounter(iv, iv_len, counter);
        
        // 步骤3: 加密计数器用于GHASH
        uint8_t e_counter0[16];
        SM4::encrypt(counter, e_counter0, key);
        
        // 步骤4: 计算GHASH (在解密前计算以验证标签)
        uint8_t s[16];
        ghash(H, aad, aad_len, ciphertext, ciphertext_len, s);
        
        // 步骤5: 验证标签
        uint8_t computed_tag[16] = {0};
        for (size_t i = 0; i < tag_len; i++) {
            computed_tag[i] = e_counter0[i] ^ s[i];
        }
        
        if (memcmp(computed_tag, tag, tag_len) != 0) {
            // 认证失败
            return false;
        }
        
        // 步骤6: CTR模式解密
        uint8_t current_counter[16];
        memcpy(current_counter, counter, 16);
        incrementCounter(current_counter); // 从J0+1开始
        
        size_t blocks = ciphertext_len / 16;
        size_t remaining = ciphertext_len % 16;
        
        // 处理完整块
        for (size_t i = 0; i < blocks; i++) {
            uint8_t e_counter[16];
            SM4::encrypt(current_counter, e_counter, key);
            
            // 与密文异或
            for (int j = 0; j < 16; j++) {
                plaintext[i*16 + j] = ciphertext[i*16 + j] ^ e_counter[j];
            }
            incrementCounter(current_counter);
        }
        
        // 处理剩余部分
        if (remaining > 0) {
            uint8_t e_counter[16];
            SM4::encrypt(current_counter, e_counter, key);
            
            for (size_t j = 0; j < remaining; j++) {
                plaintext[blocks*16 + j] = ciphertext[blocks*16 + j] ^ e_counter[j];
            }
        }
        
        return true;
    }
    
    // 性能测试
    static void measurePerformance(size_t data_size) {
        // 准备测试数据
        std::vector<uint8_t> key(16, 0xAA);
        std::vector<uint8_t> iv(12, 0xBB);
        std::vector<uint8_t> aad(32, 0xCC);
        std::vector<uint8_t> plaintext(data_size, 0xDD);
        std::vector<uint8_t> ciphertext(data_size);
        std::vector<uint8_t> tag(16);
        std::vector<uint8_t> decrypted(data_size);
        
        // 预热
        encrypt(key.data(), iv.data(), iv.size(),
                aad.data(), aad.size(),
                plaintext.data(), plaintext.size(),
                ciphertext.data(), tag.data());
        
        // 加密性能测试
        auto start_enc = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10; i++) {
            encrypt(key.data(), iv.data(), iv.size(),
                    aad.data(), aad.size(),
                    plaintext.data(), plaintext.size(),
                    ciphertext.data(), tag.data());
        }
        auto end_enc = std::chrono::high_resolution_clock::now();
        
        // 解密性能测试
        auto start_dec = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10; i++) {
            bool success = decrypt(key.data(), iv.data(), iv.size(),
                                  aad.data(), aad.size(),
                                  ciphertext.data(), ciphertext.size(),
                                  tag.data(), tag.size(),
                                  decrypted.data());
            if (!success) {
                std::cerr << "解密失败!" << std::endl;
                return;
            }
        }
        auto end_dec = std::chrono::high_resolution_clock::now();
        
        // 验证解密结果
        if (memcmp(plaintext.data(), decrypted.data(), data_size) != 0) {
            std::cerr << "解密验证失败!" << std::endl;
            return;
        }
        
        // 计算吞吐量
        double enc_time = std::chrono::duration<double>(end_enc - start_enc).count() / 10;
        double dec_time = std::chrono::duration<double>(end_dec - start_dec).count() / 10;
        
        double enc_speed = (data_size / enc_time) / (1024 * 1024);
        double dec_speed = (data_size / dec_time) / (1024 * 1024);
        
        std::cout << "SM4-GCM性能测试 (" << data_size / 1024 << " KB 数据):\n";
        std::cout << "  加密时间: " << enc_time * 1000 << " ms\n";
        std::cout << "  解密时间: " << dec_time * 1000 << " ms\n";
        std::cout << "  加密速度: " << enc_speed << " MB/s\n";
        std::cout << "  解密速度: " << dec_speed << " MB/s\n";
        std::cout << "  总吞吐量: " << enc_speed + dec_speed << " MB/s\n";
    }
};

int main() {
    // 测试SM4基本功能
    {
        std::cout << "=== SM4基本功能测试 ===" << std::endl;
        uint8_t key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        
        uint8_t plaintext[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        
        uint8_t ciphertext[16];
        uint8_t decrypted[16];
        
        std::cout << "原始明文: ";
        printHex(plaintext, 16);
        
        // 加密
        SM4::encrypt(plaintext, ciphertext, key);
        std::cout << "加密结果: ";
        printHex(ciphertext, 16);
        
        // 解密
        SM4::decrypt(ciphertext, decrypted, key);
        std::cout << "解密结果: ";
        printHex(decrypted, 16);
        
        // 验证解密结果
        if (memcmp(plaintext, decrypted, 16) == 0) {
            std::cout << "SM4解密成功!" << std::endl;
        } else {
            std::cout << "SM4解密失败!" << std::endl;
        }
        std::cout << std::endl;
    }
    
    // 测试SM4-GCM功能
    {
        std::cout << "=== SM4-GCM功能测试 ===" << std::endl;
        uint8_t key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        uint8_t iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                          0x08, 0x09, 0x0A, 0x0B};
        uint8_t aad[32] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                           0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                           0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                           0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
        const char* plaintext_str = "百慕大仓库测试SM4-GCM模式。";
        size_t data_len = strlen(plaintext_str);
        std::vector<uint8_t> plaintext(data_len);
        memcpy(plaintext.data(), plaintext_str, data_len);
        
        std::vector<uint8_t> ciphertext(data_len);
        std::vector<uint8_t> tag(16);
        std::vector<uint8_t> decrypted(data_len);
        
        std::cout << "原始明文: " << plaintext_str << "\n";
        
        // 加密
        try {
            SM4_GCM::encrypt(key, iv, sizeof(iv),
                         aad, sizeof(aad),
                         plaintext.data(), data_len,
                         ciphertext.data(), tag.data());
        } catch (const std::exception& e) {
            std::cerr << "加密错误: " << e.what() << std::endl;
            return 1;
        }
        
        std::cout << "加密成功! 密文长度: " << data_len << " 字节\n";
        std::cout << "认证标签: ";
        printHex(tag.data(), 16);
        
        // 篡改测试 (取消注释进行测试)
        // ciphertext[0] ^= 0x01; // 修改一个字节
        
        // 解密
        bool success = SM4_GCM::decrypt(key, iv, sizeof(iv),
                                   aad, sizeof(aad),
                                   ciphertext.data(), data_len,
                                   tag.data(), tag.size(),
                                   decrypted.data());
        
        if (success) {
            // 添加字符串结束符
            decrypted.push_back(0);
            std::cout << "解密成功! 解密结果: " << decrypted.data() << "\n";
        } else {
            std::cout << "解密失败! 认证标签不匹配!\n";
        }
        std::cout << std::endl;
    }
    
    // 性能测试
    std::cout << "=== SM4-GCM性能测试 ===" << std::endl;
    SM4_GCM::measurePerformance(16 * 1024);      // 16KB
    SM4_GCM::measurePerformance(1024 * 1024);    // 1MB
    SM4_GCM::measurePerformance(16 * 1024 * 1024); // 16MB
    
    return 0;
}
