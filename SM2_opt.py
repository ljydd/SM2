import random
from typing import Tuple, Optional, List

class SM2:
    # SM2推荐参数 (256位素数域) - 设为类属性避免每个实例重复存储
    p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
    a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
    b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
    n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
    Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
    Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
    G = (Gx, Gy)
    h = 1  # 余因子
    
    # 预计算表
    _precompute_table: List[Optional[Tuple[int, int]]] = []
    
    def __init__(self, precompute_window_size: int = 4):
        """初始化SM2曲线
        
        Args:
            precompute_window_size: 预计算窗口大小，默认为4
        """
        self.precompute_window_size = precompute_window_size
        self._build_precompute_table()
    
    def _build_precompute_table(self):
        """构建预计算表加速标量乘法"""
        if not self._precompute_table:
            table_size = 1 << self.precompute_window_size
            self._precompute_table = [None] * table_size
            self._precompute_table[0] = (0, 0)  # 无穷远点
            self._precompute_table[1] = self.G
            
            for i in range(2, table_size):
                self._precompute_table[i] = self.point_add(
                    self._precompute_table[i-1], self.G)
    
    def key_gen(self) -> Tuple[int, Tuple[int, int]]:
        """生成SM2密钥对"""
        d = random.randint(1, self.n-1)
        P = self.optimized_scalar_mul(d, self.G)
        return d, P
    
    def optimized_scalar_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """优化的椭圆曲线标量乘法 (滑动窗口法)
        
        Args:
            k: 标量
            P: 椭圆曲线点
            
        Returns:
            标量乘法结果 k*P
        """
        # 如果P是基点且预计算表可用，使用预计算表
        if P == self.G and self._precompute_table:
            return self._windowed_scalar_mul(k)
        return self._sliding_window_scalar_mul(k, P)
    
    def _windowed_scalar_mul(self, k: int) -> Tuple[int, int]:
        """使用预计算表的窗口法标量乘法"""
        k = k % self.n
        if k == 0:
            return (0, 0)
        
        # 将k分解为多个窗口
        window_size = self.precompute_window_size
        num_windows = (k.bit_length() + window_size - 1) // window_size
        windows = []
        for i in range(num_windows):
            window = (k >> (i * window_size)) & ((1 << window_size) - 1)
            windows.append(window)
        
        # 从最高位窗口开始处理
        Q = (0, 0)
        for i in reversed(range(len(windows))):
            for _ in range(window_size):
                Q = self.point_double(Q)
            if windows[i] > 0:
                Q = self.point_add(Q, self._precompute_table[windows[i]])
        return Q
    
    def _sliding_window_scalar_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """滑动窗口法标量乘法"""
        k = k % self.n
        if k == 0:
            return (0, 0)
        
        window_size = self.precompute_window_size
        max_val = 1 << window_size
        # 预计算 [P, 3P, 5P, ..., (2^window_size-1)P]
        precomp = [None] * max_val
        precomp[0] = (0, 0)
        precomp[1] = P
        for i in range(2, max_val):
            if i % 2 == 0:
                precomp[i] = self.point_double(precomp[i//2])
            else:
                precomp[i] = self.point_add(precomp[i-1], P)
        
        # 滑动窗口处理
        Q = (0, 0)
        i = k.bit_length() - 1
        while i >= 0:
            if not (k >> i) & 1:
                Q = self.point_double(Q)
                i -= 1
            else:
                # 找到最长的奇数窗口
                l = max(i - window_size + 1, 0)
                while not (k >> l) & 1:
                    l += 1
                # 处理窗口
                for _ in range(i - l + 1):
                    Q = self.point_double(Q)
                window = (k >> l) & ((1 << (i - l + 1)) - 1)
                if window > 0:
                    Q = self.point_add(Q, precomp[window])
                i = l - 1
        return Q
    
    def scalar_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线标量乘法 (兼容旧接口)"""
        return self.optimized_scalar_mul(k, P)
    
    def point_add(self, P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """优化的椭圆曲线点加法"""
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0]:
            if P[1] == Q[1]:
                return self.point_double(P)
            return None  # P + (-P) = 无穷远点
            
        x1, y1 = P
        x2, y2 = Q
        
        # 优化模逆计算
        dx = (x2 - x1) % self.p
        dy = (y2 - y1) % self.p
        inv_dx = self._mod_inv(dx)
        lam = (dy * inv_dx) % self.p
        
        x3 = (lam**2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)
    
    def point_double(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """优化的椭圆曲线点加倍"""
        x1, y1 = P
        
        # 优化模逆计算
        inv_2y1 = self._mod_inv((2 * y1) % self.p)
        lam = ((3 * x1**2 + self.a) * inv_2y1) % self.p
        
        x3 = (lam**2 - 2 * x1) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)
    
    def _mod_inv(self, x: int) -> int:
        """优化的模逆计算 (使用扩展欧几里得算法)"""
        # 由于p是素数，可以使用费马小定理: x^-1 ≡ x^(p-2) mod p
        return pow(x, self.p-2, self.p)
    
    def _mod_mul(self, a: int, b: int) -> int:
        """优化的模乘计算"""
        return (a * b) % self.p

# 测试代码
if __name__ == "__main__":
    sm2 = SM2(precompute_window_size=4)
    private_key, public_key = sm2.key_gen()
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: ({hex(public_key[0])}, {hex(public_key[1])})")
    
    # 性能测试
    import time
    start = time.time()
    for _ in range(10):
        sm2.scalar_mul(private_key, sm2.G)
    end = time.time()
    print(f"10次标量乘法平均时间: {(end-start)/10:.4f}秒")