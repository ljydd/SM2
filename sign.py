from hashlib import sha256
import ecdsa

# 创世区块数据
msg = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
pubkey_hex = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
signature_der = bytes.fromhex(
    "3045022100678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb022049f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)

# 验证
vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey_hex[2:]), curve=ecdsa.SECP256k1)
try:
    vk.verify(signature_der, msg, hashfunc=sha256)
    print("签名验证通过！")
except ecdsa.BadSignatureError:
    print("签名无效！")