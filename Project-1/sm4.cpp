#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <vector>

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

int main() {
    // 测试数据
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
        std::cout << "解密成功!" << std::endl;
    } else {
        std::cout << "解密失败!" << std::endl;
    }
    
    // 时间测量
    const int ITERATIONS = 10000;
    const size_t DATA_SIZE = 1024; // 1KB数据
    
    // 准备测试数据
    std::vector<uint8_t> testData(DATA_SIZE, 0xAA);
    
    // 测量加密时间
    double encryptTime = SM4::measureEncryptTime(testData.data(), DATA_SIZE, key, ITERATIONS);
    if (encryptTime > 0) {
        double speed = (DATA_SIZE * ITERATIONS) / (encryptTime * 1000000); // MB/s
        std::cout << "\n加密性能测试 (" << ITERATIONS << " 次迭代, " 
                  << DATA_SIZE << " 字节每次):" << std::endl;
        std::cout << "总时间: " << encryptTime * 1000 << " ms" << std::endl;
        std::cout << "平均加密时间: " << encryptTime * 1000 << " ms" << std::endl;
        std::cout << "吞吐量: " << speed << " MB/s" << std::endl;
    }
    
    // 测量解密时间
    double decryptTime = SM4::measureDecryptTime(testData.data(), DATA_SIZE, key, ITERATIONS);
    if (decryptTime > 0) {
        double speed = (DATA_SIZE * ITERATIONS) / (decryptTime * 1000000); // MB/s
        std::cout << "\n解密性能测试 (" << ITERATIONS << " 次迭代, " 
                  << DATA_SIZE << " 字节每次):" << std::endl;
        std::cout << "总时间: " << decryptTime * 1000 << " ms" << std::endl;
        std::cout << "平均解密时间: " << decryptTime * 1000 << " ms" << std::endl;
        std::cout << "吞吐量: " << speed << " MB/s" << std::endl;
    }
    
    return 0;
}