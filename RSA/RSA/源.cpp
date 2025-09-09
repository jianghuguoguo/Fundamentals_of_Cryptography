#include <iostream>
using namespace std;

// ��չŷ������㷨����Ԫ
long long inverse(long long e, long long phi) {
    long long x0 = 0, x1 = 1;
    long long m0 = phi;
    while (phi != 0) {
        long long q = e / phi;
        long long t = phi;

        phi = e % phi;
        e = t;

        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (e != 1) return -1; // �޽�
    return (x1 + m0) % m0;
}


// �üӷ�����˷���ֹ��������㣨A*B (mod n)��
long long mul_mod(long long a, long long b, long long mod) {
    long long result = 0;
    a %= mod;
    b %= mod;
    while (b > 0) {
        if (b & 1) {
            result = (result + a) % mod;
        }
        a = (a + a) % mod;
        b >>= 1;
    }
    return result;
}

// ƽ�����㷨
long long pow_mod(long long base, long long exponent, long long mod) {
    long long result = 1;
    base %= mod;//������ȡģ
    while (exponent > 0) {
        if (exponent & 1)//ָ�����λ��1�Ļ�����һ�����ƽ���ȳ�һ������
            result = mul_mod(result, base, mod);
        base = mul_mod(base, base, mod);//������һ�������ƽ��
        exponent >>= 1;
    }
    return result;
}

int main() {
    long long p, q, e, c;
    cin >> p >> q >> e >> c;

    const long long n = p * q;
    const long long phi = (p - 1) * (q - 1);

    long long d = inverse(e, phi);
    long long m = pow_mod(c, d, n);
    cout << m;
    return 0;
}
