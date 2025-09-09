#include <iostream>
#include <vector>
#include <bitset>
using namespace std;
int S[16] = { 0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7 };
int P[16] = { 1,5, 9, 13, 2, 6,10,14,3,7,11,15,4,8,12,16};

// ʵ��S���滻
unsigned short s(unsigned short u) {
    unsigned short v = 0;
    for (int i = 0; i < 4; ++i) {
        int replace = (u >> (i * 4)) & 0xF;//������λ�����룬ȡ����ǰ����λ
        v |= (S[replace] << (i * 4));//�滻
    }
    return v;
}

// ʵ��P���û�
unsigned short p(unsigned short v) {
    unsigned short w = 0;
    for (int i = 0; i < 16; ++i) {
        int src = 16 - P[i];//bitsetĬ�ϸ�λ�ں��λ��ǰ������ԭ����λ
        int bit = (v >> src) & 1;//ȡ����λ
        w |= (bit << (15-i));//���������ȷ��λ����
    }
    return w;
}

// SPN����
unsigned short spn(unsigned short plaintext, vector<unsigned short> keys) {
    unsigned short x = plaintext;
    for (int i = 0; i < 3; ++i) {
        x ^= keys[i];
        x = s(x);
        x = p(x);
    }
    //���һ�ֲ��ý���P�û���Ҫ�����һ������Կ�ڽ���һ�����
    x ^= keys[3];
    x = s(x);
    x ^= keys[4];
    return x;
}

// �Ӷ������ַ���ת��Ϊunsigned short
unsigned short toshort(const string& binStr) {
    return static_cast<unsigned short>(bitset<16>(binStr).to_ulong());
}

// ������Կ�ӿ�
vector<unsigned short> subkeys(string K) {
    unsigned int key=static_cast<unsigned int>(bitset<32>(K).to_ulong());//������unsiged int
    vector<unsigned short> subkeys(5);
    for (int i = 0; i < 5; ++i) {
        subkeys[i] = (key >> (16 - i * 4)) & 0xFFFF;//ÿ����ȡ����Կ�Ĳ�ͬ����
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
        if (i % 4 == 0)cout << ' ';//ÿ��λ��һ���ո񷽱�۲�
    }*/
    cout << bitset<16>(ciphertext) << endl;
    return 0;
}
