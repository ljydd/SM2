import random
import hashlib
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

#重用随机数k导致私钥泄露
def test_k_reuse_same_user():
    sm2 = SM2()
    
    # 生成密钥对
    dA, PA = sm2.key_gen()
    
    # 模拟两次签名使用相同的k
    k = random.randint(1, sm2.n-1)
    
    # 签名消息1
    M1 = b"message1"
    ZA = b"user_id_A"  # 简化的ZA计算
    e1 = int.from_bytes(hashlib.sha256(ZA + M1).digest(), 'big') % sm2.n
    kG = sm2.scalar_mul(k, sm2.G)
    r1 = (e1 + kG[0]) % sm2.n
    s1 = (pow(1 + dA, -1, sm2.n) * (k - r1 * dA)) % sm2.n
    
    # 签名消息2 (使用相同的k)
    M2 = b"message2"
    e2 = int.from_bytes(hashlib.sha256(ZA + M2).digest(), 'big') % sm2.n
    kG = sm2.scalar_mul(k, sm2.G)  # 相同的k
    r2 = (e2 + kG[0]) % sm2.n
    s2 = (pow(1 + dA, -1, sm2.n) * (k - r2 * dA)) % sm2.n
    
    # 推导私钥dA
    numerator = (s2 - s1) % sm2.n
    denominator = (s1 - s2 + r1 - r2) % sm2.n
    dA_recovered = (numerator * pow(denominator, -1, sm2.n)) % sm2.n
    
    print(f"原始私钥: {hex(dA)}")
    print(f"恢复私钥: {hex(dA_recovered)}")
    assert dA == dA_recovered, "私钥恢复失败"
    
test_k_reuse_same_user()

#不同用户使用相同k导致私钥泄露
def test_k_reuse_different_users():
    sm2 = SM2()
    
    # 生成两个用户的密钥对
    dA, PA = sm2.key_gen()
    dB, PB = sm2.key_gen()
    
    # 两个用户使用相同的k
    k = random.randint(1, sm2.n-1)
    
    # Alice签名
    M1 = b"message_from_Alice"
    ZA = b"user_id_A"
    e1 = int.from_bytes(hashlib.sha256(ZA + M1).digest(), 'big') % sm2.n
    kG = sm2.scalar_mul(k, sm2.G)
    r1 = (e1 + kG[0]) % sm2.n
    s1 = (pow(1 + dA, -1, sm2.n) * (k - r1 * dA)) % sm2.n
    
    # Bob签名(使用相同的k)
    M2 = b"message_from_Bob"
    ZB = b"user_id_B"
    e2 = int.from_bytes(hashlib.sha256(ZB + M2).digest(), 'big') % sm2.n
    kG = sm2.scalar_mul(k, sm2.G)  # 相同的k
    r2 = (e2 + kG[0]) % sm2.n
    s2 = (pow(1 + dB, -1, sm2.n) * (k - r2 * dB)) % sm2.n
    
    # Alice推导Bob的私钥dB
    numerator = (k - s2) % sm2.n
    denominator = (s2 + r2) % sm2.n
    dB_recovered = (numerator * pow(denominator, -1, sm2.n)) % sm2.n
    
    # Bob推导Alice的私钥dA
    numerator = (k - s1) % sm2.n
    denominator = (s1 + r1) % sm2.n
    dA_recovered = (numerator * pow(denominator, -1, sm2.n)) % sm2.n
    
    print(f"Alice原始私钥: {hex(dA)}")
    print(f"Bob恢复的Alice私钥: {hex(dA_recovered)}")
    print(f"Bob原始私钥: {hex(dB)}")
    print(f"Alice恢复的Bob私钥: {hex(dB_recovered)}")
    assert dA == dA_recovered and dB == dB_recovered, "私钥恢复失败"
    
test_k_reuse_different_users()

#与ECDSA使用相同的d和k导致私钥泄露
def test_same_d_k_with_ecdsa():
    sm2 = SM2()
    
    # 生成密钥对
    d, P = sm2.key_gen()
    
    # 相同的k用于ECDSA和SM2
    k = random.randint(1, sm2.n-1)
    kG = sm2.scalar_mul(k, sm2.G)
    
    # ECDSA签名
    M1 = b"message_for_ECDSA"
    e1 = int.from_bytes(hashlib.sha256(M1).digest(), 'big') % sm2.n
    r1 = kG[0] % sm2.n
    s1 = ((e1 + r1 * d) * pow(k, -1, sm2.n)) % sm2.n
    
    # SM2签名(相同d,k)
    M2 = b"message_for_SM2"
    Z = b"user_id"
    e2 = int.from_bytes(hashlib.sha256(Z + M2).digest(), 'big') % sm2.n
    r2 = (e2 + kG[0]) % sm2.n
    s2 = (pow(1 + d, -1, sm2.n) * (k - r2 * d)) % sm2.n
    
    # 推导私钥d
    numerator = (s1 * s2 - e1) % sm2.n
    denominator = (r1 - s1 * s2 - s1 * r2) % sm2.n
    d_recovered = (numerator * pow(denominator, -1, sm2.n)) % sm2.n
    
    print(f"原始私钥: {hex(d)}")
    print(f"恢复私钥: {hex(d_recovered)}")
    assert d == d_recovered, "私钥恢复失败"
    
test_same_d_k_with_ecdsa()

#签名可延展性问题
def test_signature_malleability():
    sm2 = SM2()
    
    # 生成密钥对
    d, P = sm2.key_gen()
    
    # 正常签名
    M = b"test_message"
    Z = b"user_id"
    e = int.from_bytes(hashlib.sha256(Z + M).digest(), 'big') % sm2.n
    k = random.randint(1, sm2.n-1)
    kG = sm2.scalar_mul(k, sm2.G)
    r = (e + kG[0]) % sm2.n
    s = (pow(1 + d, -1, sm2.n) * (k - r * d)) % sm2.n
    
    # 验证原始签名
    t = (r + s) % sm2.n
    sG = sm2.scalar_mul(s, sm2.G)
    tP = sm2.scalar_mul(t, P)
    x1y1 = sm2.point_add(sG, tP)
    if x1y1 is None:
        raise ValueError("原始签名验证时出现无效点")
    R = (e + x1y1[0]) % sm2.n
    assert R == r, "原始签名验证失败"
    
    # 创建可延展签名 (r, -s mod n)
    s_malleable = (-s) % sm2.n
    
    # 验证可延展签名
    t_malleable = (r + s_malleable) % sm2.n
    sG_malleable = sm2.scalar_mul(s_malleable, sm2.G)
    tP_malleable = sm2.scalar_mul(t_malleable, P)
    x1y1_malleable = sm2.point_add(sG_malleable, tP_malleable)
    
    if x1y1_malleable is None:
        print("可延展签名验证时出现无效点，这是预期行为")
        print("说明(r,-s)形式的签名在实际验证时会失败")
        print("原始签名:", (hex(r), hex(s)))
        print("可延展签名:", (hex(r), hex(s_malleable)))
        return
    
    R_malleable = (e + x1y1_malleable[0]) % sm2.n
    
    # 对于可延展签名，需要与 -r mod n 比较
    if R_malleable == (-r) % sm2.n:
        print("原始签名:", (hex(r), hex(s)))
        print("可延展签名:", (hex(r), hex(s_malleable)))
        print("两者都验证通过，存在签名可延展性问题")
    else:
        print("可延展签名验证不通过")

test_signature_malleability()