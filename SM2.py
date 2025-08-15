import random
from typing import Tuple, Optional

class SM2:
    def __init__(self):
        # SM2推荐参数 (256位素数域)
        self.p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
        self.a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
        self.b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
        self.n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
        self.Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
        self.Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
        self.G = (self.Gx, self.Gy)
        self.h = 1  # 余因子

    def key_gen(self) -> Tuple[int, Tuple[int, int]]:
        """生成SM2密钥对"""
        d = random.randint(1, self.n-1)
        P = self.scalar_mul(d, self.G)
        return d, P

    def scalar_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线标量乘法 (double-and-add算法)"""
        Q = None
        for i in reversed(range(k.bit_length())):
            if Q is not None:
                Q = self.point_double(Q)
            if (k >> i) & 1:
                Q = self.point_add(Q, P) if Q is not None else P
        return Q or (0, 0)

    def point_add(self, P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """椭圆曲线点加法"""
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and P[1] != Q[1]:
            return None
            
        if P == Q:
            return self.point_double(P)
            
        x1, y1 = P
        x2, y2 = Q
        lam = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        x3 = (lam**2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def point_double(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加倍"""
        x1, y1 = P
        lam = (3 * x1**2 + self.a) * pow(2 * y1, -1, self.p) % self.p
        x3 = (lam**2 - 2 * x1) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

# 测试代码
if __name__ == "__main__":
    sm2 = SM2()
    private_key, public_key = sm2.key_gen()
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: ({hex(public_key[0])}, {hex(public_key[1])})")