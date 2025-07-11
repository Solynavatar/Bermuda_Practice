#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <chrono>

class SM3 {
private:
    static const uint32_t IV[8];
    static const uint32_t T[64];

    static inline uint32_t ROTL(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t P0(uint32_t x) {
        return x ^ ROTL(x, 9) ^ ROTL(x, 17);
    }

    static inline uint32_t P1(uint32_t x) {
        return x ^ ROTL(x, 15) ^ ROTL(x, 23);
    }

    static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    static std::vector<uint8_t> pad(const uint8_t* data, size_t len) {
        size_t bitLen = len * 8;
        size_t k = (448 - (bitLen + 1) % 512 + 512) % 512;
        size_t paddedLen = len + (k + 1 + 64) / 8;

        std::vector<uint8_t> res(paddedLen, 0);
        memcpy(res.data(), data, len);
        res[len] = 0x80;

        for (int i = 0; i < 8; ++i) {
            res[paddedLen - 1 - i] = (bitLen >> (8 * i)) & 0xFF;
        }
        return res;
    }

public:
    static void hash(const uint8_t* data, size_t len, uint8_t digest[32]) {
        uint32_t V[8];
        memcpy(V, IV, sizeof(V));

        std::vector<uint8_t> msg = pad(data, len);
        size_t blocks = msg.size() / 64;

        for (size_t i = 0; i < blocks; ++i) {
            uint32_t W[68], W1[64];
            const uint8_t* B = msg.data() + i * 64;

            // 消息扩展合并
            for (int j = 0; j < 16; ++j) {
                W[j] = (B[j*4] << 24) | (B[j*4+1] << 16) | (B[j*4+2] << 8) | B[j*4+3];
            }
            for (int j = 16; j < 68; ++j) {
                W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j-13],7) ^ W[j-6];
            }
            for (int j = 0; j < 64; ++j) {
                W1[j] = W[j] ^ W[j+4];
            }

            uint32_t A=V[0], B_=V[1], C=V[2], D=V[3];
            uint32_t E=V[4], F=V[5], G=V[6], H=V[7];

            // 循环展开，每次处理8轮
            for (int j = 0; j < 64; j+=8) {
                for (int k = 0; k < 8; ++k) {
                    uint32_t SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j+k], j+k)) & 0xFFFFFFFF, 7);
                    uint32_t SS2 = SS1 ^ ROTL(A,12);
                    uint32_t TT1 = (FF(A,B_,C,j+k) + D + SS2 + W1[j+k]) & 0xFFFFFFFF;
                    uint32_t TT2 = (GG(E,F,G,j+k) + H + SS1 + W[j+k]) & 0xFFFFFFFF;
                    D=C; C=ROTL(B_,9); B_=A; A=TT1;
                    H=G; G=ROTL(F,19); F=E; E=P0(TT2);
                }
            }

            V[0]^=A; V[1]^=B_; V[2]^=C; V[3]^=D;
            V[4]^=E; V[5]^=F; V[6]^=G; V[7]^=H;
        }

        for (int i=0;i<8;i++) {
            digest[i*4]=(V[i]>>24)&0xFF;
            digest[i*4+1]=(V[i]>>16)&0xFF;
            digest[i*4+2]=(V[i]>>8)&0xFF;
            digest[i*4+3]=V[i]&0xFF;
        }
    }
};

const uint32_t SM3::IV[8] = {
    0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};

const uint32_t SM3::T[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
};

void printHex(const uint8_t* d, size_t len) {
    for (size_t i=0;i<len;i++)
        std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<int(d[i]);
    std::cout<<std::dec<<std::endl;
}

int main(){
    const size_t dataSize=1024*1024; // 1MB
    std::vector<uint8_t> data(dataSize,0xAA);
    uint8_t digest[32];

    // 预热
    SM3::hash(data.data(), data.size(), digest);

    auto start=std::chrono::high_resolution_clock::now();
    SM3::hash(data.data(), data.size(), digest);
    auto end=std::chrono::high_resolution_clock::now();

    double ms=std::chrono::duration<double>(end-start).count()*1000;
    std::cout<<"数据大小: "<<dataSize/1024<<" KB"<<std::endl;
    std::cout<<"SM3 哈希耗时: "<<ms<<" ms"<<std::endl;
    std::cout<<"哈希值: ";
    printHex(digest,32);
    return 0;
}
