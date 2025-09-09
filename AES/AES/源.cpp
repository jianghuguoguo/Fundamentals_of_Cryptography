#include <iostream>
#include <iomanip>
#include <sstream>
#include <array>
#include <cstdint>

using namespace std;
using Block = array<uint8_t, 16>;
using Key = array<uint8_t, 16>;
using RoundKeys = array<uint8_t, 176>; // AES-128: 11 �� * 16�ֽ� = 176�ֽ�

//S��
static const uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

//���������ֽڳ˷���
uint8_t xtime(uint8_t x) {
    // xtime(x) = x * 2 in G(2^8)
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

uint8_t mul(uint8_t x, uint8_t y) {
    // G(2^8) ���ڵĳ˷�
    uint8_t r = 0;
    while (y) {
        if (y & 1) r ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return r;
}

// ��Կ��չ����
void KeyExpansion(const Key& key, RoundKeys& roundKeys) {
    static const uint8_t Rcon[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36
    };

    for (int i = 0; i < 16; ++i)
        roundKeys[i] = key[i];

    uint8_t temp[4];
    int i = 16;
    int rconIndex = 0;

    while (i < 176) {
        for (int j = 0; j < 4; ++j)
            temp[j] = roundKeys[i - 4 + j];

        if (i % 16 == 0) {
            // ѭ����λ
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            //S���滻
            for (int j = 0; j < 4; ++j)
                temp[j] = sbox[temp[j]];
            // ��Rcon���
            temp[0] ^= Rcon[rconIndex++];
        }

        for (int j = 0; j < 4; ++j) {
            roundKeys[i] = roundKeys[i - 16] ^ temp[j];
            ++i;
        }
    }
}

//״̬��������,S���滻
void SubBytes(Block& state) {
    for (auto& b : state)
        b = sbox[b];
}

void ShiftRows(Block& state) {
    // Row 1:���͵���λ�����ⲻ��Ҫ�ĸ��ƿ�����
    uint8_t temp1 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp1;

    // Row 2:
    uint8_t temp2 = state[2], temp6 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp2;
    state[14] = temp6;

    // Row 3: 
    uint8_t temp15 = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp15;
}

//�л�������
void MixColumns(Block& state) {
    for (int i = 0; i < 4; ++i) {
        int col = i * 4;
        uint8_t a = state[col];
        uint8_t b = state[col + 1];
        uint8_t c = state[col + 2];
        uint8_t d = state[col + 3];

        state[col] = mul(a, 2) ^ mul(b, 3) ^ c ^ d;
        state[col + 1] = a ^ mul(b, 2) ^ mul(c, 3) ^ d;
        state[col + 2] = a ^ b ^ mul(c, 2) ^ mul(d, 3);
        state[col + 3] = mul(a, 3) ^ b ^ c ^ mul(d, 2);
    }
}
//����Կ�Ӻ���
void AddRoundKey(Block& state, const RoundKeys& roundKeys, int round) {
    for (int i = 0; i < 16; ++i)
        state[i] ^= roundKeys[round * 16 + i];
}

//AES ����������
void AES_encrypt(Block& input, const Key& key) {
    RoundKeys roundKeys;
    KeyExpansion(key, roundKeys);

    AddRoundKey(input, roundKeys, 0);

    for (int round = 1; round < 10; ++round) {
        SubBytes(input);
        ShiftRows(input);
        MixColumns(input);
        AddRoundKey(input, roundKeys, round);
    }
    // ���һ�ֲ������л���
    SubBytes(input);
    ShiftRows(input);
    AddRoundKey(input, roundKeys, 10);
}
// ����16�ֽ�16�����ַ���ΪBlock
Block hexstr_to_block(const string& hex) {
    Block b = {};
    for (int i = 0; i < 16; ++i) {
        string byte = hex.substr(i * 2, 2);
        b[i] = static_cast<uint8_t>(stoi(byte, nullptr, 16));
    }
    return b;
}


// ������
int main() {
    string key_str, pt_str;
    //cout << "Input:(Key & Plaintext Сд 16 ����)" << endl;
    cin >> key_str;
    cin >> pt_str;

    Key key = hexstr_to_block(key_str);
    Block plaintext = hexstr_to_block(pt_str);

    AES_encrypt(plaintext, key);

    //cout << "Output: ��Ciphertext ��д 16 ���ƣ�" << endl;
    for (size_t i = 0; i < plaintext.size(); ++i)
        printf("%02X", plaintext[i]);


    return 0;
}
