#include <iostream>
using namespace std;

typedef long long ll;
const pair<ll, ll> INF = { -1, -1 };

// 快速幂取模
ll mod_pow(ll base, ll exp, ll mod) {
    ll result = 1;
    base %= mod;
    while (exp) {
        if (exp & 1)
            result = result * base % mod;
        base = base * base % mod;
        exp >>= 1;
    }
    return result;
}

// 求模逆元
ll mod_inv(ll a, ll p) {
    return mod_pow(a, p - 2, p);
}

// 椭圆曲线加法
pair<ll, ll> point_add(pair<ll, ll> P, pair<ll, ll> Q, ll a, ll p) {
    if (P == INF) return Q;
    if (Q == INF) return P;

    ll x1 = P.first, y1 = P.second;
    ll x2 = Q.first, y2 = Q.second;

    if (x1 == x2 && (y1 + y2) % p == 0)
        return INF;

    ll s;
    if (P != Q) {
        s = ((y2 - y1 + p) * mod_inv((x2 - x1 + p) % p, p)) % p;
    }
    else {
        s = ((3 * x1 % p * x1 % p + a) * mod_inv((2 * y1) % p, p)) % p;
    }

    ll x3 = (s * s - x1 - x2 + p + p) % p;
    ll y3 = (s * (x1 - x3 + p) - y1 + p) % p;
    return { x3, y3 };
}

int solve(ll a, ll b, ll p, ll x, ll y, ll X, ll Y) {
    pair<ll, ll> P = { x, y };
    pair<ll, ll> Q = { X, Y };

    if (Q == INF)
        return 0;

    pair<ll, ll> R = INF;
    for (int k = 1; k < (1 << 16); ++k) {
        R = point_add(R, P, a, p);
        if (R == Q)
            return k;
    }
    return 0;
}

int main() {
    ll a, b, p;
    cin >> a >> b >> p;
    ll x, y, X, Y;
    cin >> x >> y >> X >> Y;

    cout << solve(a, b, p, x, y, X, Y);
}
