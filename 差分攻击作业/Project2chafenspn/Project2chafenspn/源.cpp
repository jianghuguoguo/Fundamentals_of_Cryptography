#include <iostream>
#include <vector>
#include <bitset>
#include <random>
#include <tuple>
#include <algorithm>

using namespace std;
/*******************************************************************
此代码大致思维导图框架：
SPN加密与差分攻击分析
├─ SPN结构
│  ├─ S盒/逆S盒
│  ├─ P盒置换
│  ├─ 子密钥生成（32→5×16位）
│  └─ 加密流程（异或→S→P→异或）
├─ 差分攻击
│  ├─ 数据生成（Δx=0x0A00等）
│  ├─ 攻击步骤
│  │  ├─ 筛选条件（y₁=y₁' ∧ y₃=y₃'）
│  │  ├─ 逆S盒差分验证（Δu=0x6）
│  │  └─ 统计最大计数确定密钥
│  └─ 成功率测试（多Δx对比）
└─ 测试结果
   ├─ 单次攻击验证（恢复L1/L2）
   └─ 差分影响（更换不同输入差分与成功率关系）
***********************************************************************/

//一、SPN加密结构
//**********************************************************************
// S盒与P盒
int S[16] = { 0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7 };
int P[16] = { 1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16 };

// 逆S盒（手动计算，匹配S盒）
uint8_t inv_s_box[16];
void buildInvSBox() {
    for (int i = 0; i < 16; i++) {
        inv_s_box[S[i]] = i;
    }
}

// S盒替换
unsigned short s(unsigned short u) {
    unsigned short v = 0;
    for (int i = 0; i < 4; ++i) {
        int replace = (u >> (i * 4)) & 0xF;
        v |= (S[replace] << (i * 4));
    }
    return v;
}

// P盒置换
unsigned short p(unsigned short v) {
    unsigned short w = 0;
    for (int i = 0; i < 16; ++i) {
        int src = 16 - P[i];
        int bit = (v >> src) & 1;
        w |= (bit << (15 - i));
    }
    return w;
}

// SPN加密
unsigned short spn(unsigned short plaintext, vector<unsigned short> keys) {
    unsigned short x = plaintext;
    for (int i = 0; i < 3; ++i) {
        x ^= keys[i];
        x = s(x);
        x = p(x);
    }
    x ^= keys[3];
    x = s(x);
    x ^= keys[4];
    return x;
}

// 明文与密钥输入转换
unsigned short toshort(const string& binStr) {
    return static_cast<unsigned short>(bitset<16>(binStr).to_ulong());
}

// 生成子密钥
vector<unsigned short> subkeys(string K) {
    uint32_t key = bitset<32>(K).to_ulong();
    vector<unsigned short> subkeys(5);
    for (int i = 0; i < 5; ++i) {
        subkeys[i] = (key >> (4 * (4 - i))) & 0xFFFF;
    }
    return subkeys;
}
//SPN加密结构结束


// *************************************************************************************
// 二、差分攻击结构
struct CipherPair {
    uint16_t x;
    uint16_t y;
    uint16_t x_prime;
    uint16_t y_prime;
};

// 随机生成差分明密文对
vector<CipherPair> generateRandomDataset(const string& K, uint16_t delta_x, int num_pairs) {
    vector<CipherPair> dataset;
    auto keys = subkeys(K);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint16_t> dist(0, 0xFFFF); // 生成16位随机明文

    for (int i = 0; i < num_pairs; ++i) {
        uint16_t x = dist(gen);
        uint16_t x_prime = x ^ delta_x;
        uint16_t y = spn(x, keys);
        uint16_t y_prime = spn(x_prime, keys);
        dataset.push_back({ x, y, x_prime, y_prime });
    }

    return dataset;
}


pair<uint8_t, uint8_t> differentialAttack(const vector<CipherPair>& T) {
    int count[16][16] = { 0 };

    for (const auto& pair : T) {
        // 分离四个半字节：y = y1 y2 y3 y4
        uint8_t y1 = (pair.y >> 12) & 0xF;
        uint8_t y2 = (pair.y >> 8) & 0xF;
        uint8_t y3 = (pair.y >> 4) & 0xF;
        uint8_t y4 = pair.y & 0xF;

        uint8_t y1p = (pair.y_prime >> 12) & 0xF;
        uint8_t y2p = (pair.y_prime >> 8) & 0xF;
        uint8_t y3p = (pair.y_prime >> 4) & 0xF;
        uint8_t y4p = pair.y_prime & 0xF;

        // 满足条件：y1 == y1' 且 y3 == y3'
        if (y1 == y1p && y3 == y3p) {
            for (uint8_t L1 = 0; L1 < 16; ++L1) {
                for (uint8_t L2 = 0; L2 < 16; ++L2) {
                    // 解密最后一轮前的值
                    uint8_t v42 = L1 ^ y2;
                    uint8_t v44 = L2 ^ y4;
                    uint8_t u42 = inv_s_box[v42];
                    uint8_t u44 = inv_s_box[v44];

                    uint8_t v42p = L1 ^ y2p;
                    uint8_t v44p = L2 ^ y4p;
                    uint8_t u42p = inv_s_box[v42p];
                    uint8_t u44p = inv_s_box[v44p];

                    // 差分是否为 0110（二进制）即 0x6
                    if ((u42 ^ u42p) == 0x6 && (u44 ^ u44p) == 0x6) {
                        count[L1][L2]++;
                        //cout << count[L1][L2] << endl;
                    }
                }
            }
        }
    }

    // 查找最大值
    int maxCount = -1;
    uint8_t maxL1 = 0, maxL2 = 0;
    for (uint8_t L1 = 0; L1 < 16; ++L1) {
        for (uint8_t L2 = 0; L2 < 16; ++L2) {
            if (count[L1][L2] > maxCount) {
                maxCount = count[L1][L2];
                maxL1 = L1;
                maxL2 = L2;
            }
        }
    }

    return { maxL1, maxL2 };
}

//********************************************************************************************
// 三、主程序
int main() {
    string K = "00111011100101001101011100101111";//可调整验证
    buildInvSBox();

    // 生成差分明密文对（Δx = 0x0A00），数量根据需要调整
    auto T = generateRandomDataset(K, 0x0A00, 100000); // 生成1000组差分对
    /*for (const auto& pair : T) {
        printf("x: 0x%04X, x': 0x%04X, y: 0x%04X, y': 0x%04X\n",
            pair.x, pair.x_prime, pair.y, pair.y_prime);
    }*/


    // 执行攻击
    pair<uint8_t, uint8_t> result = differentialAttack(T);
    uint8_t L1 = result.first;
    uint8_t L2 = result.second;

    // 打印攻击结果
    printf("Recovered subkey nibbles: L1 = 0x%X, L2 = 0x%X\n", L1, L2);

    // 打印真实密钥的L1, L2
    vector<unsigned short> keys = subkeys(K);
    uint8_t true_L1 = (keys[4] >> 8) & 0xF;
    uint8_t true_L2 = keys[4] & 0xF;
    printf("True subkey nibbles:L1 = 0x%X, L2 = 0x%X\n", true_L1, true_L2);


    printf("Key[4] = 0x%04X\n", keys[4]);
    printf("True subkey nibbles in key[4]:\n");
    printf("4 half nibbles: %X %X %X %X\n",
        (keys[4] >> 12) & 0xF,
        (keys[4] >> 8) & 0xF,
        (keys[4] >> 4) & 0xF,
        keys[4] & 0xF);

    // 记录不同输入差分的成功率
    vector<uint16_t> deltas = { 0x0A00, 0x0B00, 0x0C00, 0x0D00 ,0x0100,0x0F00,0x006,0x0060,0x3030,0x1011,0x1000,0x0040,0x00A0,0xA000,0x1111,0x1001,0x0002,0x1010}; // 输入差分示例
    vector<double> successRates; // 存储成功率
    int totalRuns = 100; // 每个输入差分进行的攻击次数

    for (uint16_t delta : deltas) {
        int successfulAttacks = 0;

        for (int i = 0; i < totalRuns; ++i) {
            auto T = generateRandomDataset(K, delta, 5000); // 生成差分明密文对
            pair<uint8_t, uint8_t> result = differentialAttack(T);

            // 假设如果攻击结果匹配真实密钥，我们算成功
            vector<unsigned short> keys = subkeys(K);
            uint8_t true_L1 = (keys[4] >> 8) & 0xF;
            uint8_t true_L2 = keys[4] & 0xF;

            if (result.first == true_L1 && result.second == true_L2) {
                successfulAttacks++;
            }
        }

        // 计算成功率
        double successRate = static_cast<double>(successfulAttacks) / totalRuns;
        successRates.push_back(successRate);
        printf("Delta: 0x%04X, Success Rate: %.2f%%\n", delta, successRate * 100);
    }
    return 0;
}

