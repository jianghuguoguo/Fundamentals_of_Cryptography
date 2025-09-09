#include <iostream>
#include <vector>
#include <bitset>
using namespace std;
int S[16] = { 0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7 };
int P[16] = { 1,5, 9, 13, 2, 6,10,14,3,7,11,15,4,8,12,16};

// 实现S盒替换
unsigned short s(unsigned short u) {
    unsigned short v = 0;
    for (int i = 0; i < 4; ++i) {
        int replace = (u >> (i * 4)) & 0xF;//右移四位，掩码，取出当前的四位
        v |= (S[replace] << (i * 4));//替换
    }
    return v;
}

// 实现P盒置换
unsigned short p(unsigned short v) {
    unsigned short w = 0;
    for (int i = 0; i < 16; ++i) {
        int src = 16 - P[i];//bitset默认高位在后低位在前，计算原比特位
        int bit = (v >> src) & 1;//取出该位
        w |= (bit << (15-i));//倒序放在正确的位置上
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
    //最后一轮不用进行P置换，要和最后一个子密钥在进行一次异或
    x ^= keys[3];
    x = s(x);
    x ^= keys[4];
    return x;
}

// 从二进制字符串转换为unsigned short
unsigned short toshort(const string& binStr) {
    return static_cast<unsigned short>(bitset<16>(binStr).to_ulong());
}

// 生成密钥子块
vector<unsigned short> subkeys(string K) {
    unsigned int key=static_cast<unsigned int>(bitset<32>(K).to_ulong());//传换成unsiged int
    vector<unsigned short> subkeys(5);
    for (int i = 0; i < 5; ++i) {
        subkeys[i] = (key >> (16 - i * 4)) & 0xFFFF;//每次提取子密钥的不同部分
    }
    return subkeys;
}

int main() {
    string x, K;
    cin >> x;
    cin >> K;

    unsigned short plaintext = toshort(x);
    vector<unsigned short> keys = subkeys(K);
    unsigned short ciphertext = spn(plaintext, keys);
    /*for (int i = 15; i >= 0; i--) {
        bitset<16> a(ciphertext);
        cout << a[i];
        if (i % 4 == 0)cout << ' ';//每四位加一个空格方便观察
    }*/
    cout << bitset<16>(ciphertext) << endl;
    return 0;
}
