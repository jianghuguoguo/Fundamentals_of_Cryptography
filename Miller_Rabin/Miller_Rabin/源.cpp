#include <iostream>
#include <vector>
using namespace std;
using ll = long long;

// 快速模乘
ll mod_mul(ll a, ll b, ll mod) {
    ll result = 0;
    a %= mod;
    while (b > 0) {
        if (b & 1) result = (result + a) % mod;
        a = (a + a) % mod;
        b >>= 1;
    }
    return result;
}

// 快速幂运算
ll mod_pow(ll base, ll exp, ll mod) {
    ll result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = mod_mul(result, base, mod);
        base = mod_mul(base, base, mod);
        exp >>= 1;
    }
    return result;
}

// Miller-Rabin 素性检测
bool is_prime(ll n) {
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;

    ll d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        s++;
    }

    vector<ll> bases = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };

    for (ll a : bases) {
        if (a >= n) break;
        ll x = mod_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;

        bool passed = false;
        for (int r = 1; r < s; ++r) {
            x = mod_mul(x, x, n);
            if (x == n - 1) {
                passed = true;
                break;
            }
        }
        if (!passed) return false;
    }
    return true;
}

int main() {
    ll n;
    cin >> n;
    cout << (is_prime(n) ? "Yes" : "No");
    return 0;
}
