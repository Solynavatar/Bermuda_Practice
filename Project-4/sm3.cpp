#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <chrono>

class SM3 {
private:
    static const uint32_t IV[8];  // 初始向量
    static const uint32_t T[64];  // 常量表

    static inline uint32_t leftRotate(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    static inline uint32_t P0(uint32_t x) {
        return x ^ leftRotate(x, 9) ^ leftRotate(x, 17);
    }

    static inline uint32_t P1(uint32_t x) {
        return x ^ leftRotate(x, 15) ^ leftRotate(x, 23);
    }

    // 填充消息
    static std::vector<uint8_t> pad(const uint8_t* data, size_t len) {
        size_t l = len * 8;
        size_t k = (448 - (l + 1) % 512 + 512) % 512;
        size_t paddedLen = len + (k + 1 + 64) / 8;

        std::vector<uint8_t> padded(paddedLen);
        memcpy(padded.data(), data, len);

        padded[len] = 0x80;
        for (int i = 0; i < 8; i++) {
            padded[paddedLen - 1 - i] = (uint8_t)((l >> (8 * i)) & 0xFF);
        }

        return padded;
    }

public:
    static void hash(const uint8_t* data, size_t len, uint8_t digest[32]) {
        uint32_t V[8];
        memcpy(V, IV, sizeof(V));

        std::vector<uint8_t> msg = pad(data, len);
        size_t numBlocks = msg.size() / 64;

        for (size_t i = 0; i < numBlocks; i++) {
            const uint8_t* block = msg.data() + i * 64;
            uint32_t W[68], W1[64];

            // 消息扩展
            for (int j = 0; j < 16; j++) {
                W[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) | (block[j * 4 + 2] << 8) | block[j * 4 + 3];
            }
            for (int j = 16; j < 68; j++) {
                W[j] = P1(W[j - 16] ^ W[j - 9] ^ leftRotate(W[j - 3], 15)) ^ leftRotate(W[j - 13], 7) ^ W[j - 6];
            }
            for (int j = 0; j < 64; j++) {
                W1[j] = W[j] ^ W[j + 4];
            }

            uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
            uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

            // 压缩函数
            for (int j = 0; j < 64; j++) {
                uint32_t SS1 = leftRotate((leftRotate(A, 12) + E + leftRotate(T[j], j)) & 0xFFFFFFFF, 7);
                uint32_t SS2 = SS1 ^ leftRotate(A, 12);
                uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
                uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;

                D = C;
                C = leftRotate(B, 9);
                B = A;
                A = TT1;
                H = G;
                G = leftRotate(F, 19);
                F = E;
                E = P0(TT2);
            }

            // 更新向量
            V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
            V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
        }

        // 输出
        for (int i = 0; i < 8; i++) {
            digest[i * 4] = (V[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (V[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (V[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = V[i] & 0xFF;
        }
    }
};

// 初始向量
const uint32_t SM3::IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 常量表
const uint32_t SM3::T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
};

// 打印哈希值
void printHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    std::cout << std::dec << std::endl;
}

int main() {
    const size_t dataSize = 1024 * 1024;  // 1 MB 测试数据
    std::vector<uint8_t> data(dataSize, 0xAA);  // 测试用内容

    uint8_t digest[32];

    // 预热
    SM3::hash(data.data(), data.size(), digest);

    // 测量时间
    auto start = std::chrono::high_resolution_clock::now();

    SM3::hash(data.data(), data.size(), digest);

    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> duration = end - start;
    double timeMs = duration.count() * 1000;

    std::cout << "数据大小: " << dataSize / 1024 << " KB" << std::endl;
    std::cout << "SM3 哈希耗时: " << timeMs << " ms" << std::endl;

    std::cout << "哈希值: ";
    printHex(digest, 32);

    return 0;
}
