#!/usr/bin/env python3

# Reconstructed from the binary:
#   v15 = Fib(N) mod 313333333337
#   mod = (31333333333337)^4
#   r = pow(v15, 3133333337, mod)
#   r = r * 1337
#   flag[i] = blob[i] XOR r_bytes_big_endian[i % len(r_bytes)]

M_FIB = 313_333_333_337          # 0x48F41F3D59
BASE_MOD = 31_333_333_333_337    # 0x1C7F5C33F559
EXP = 3_133_333_337              # 0xBA43B743
WORD_MUL = 1337

BLOB = bytes([
    0x42, 0x54, 0x8D, 0x65, 0x93, 0xF5, 0xB9, 0x24, 0xFA, 0xBF,
    0xA2, 0x91, 0xC1, 0x9C, 0xF0, 0xDB, 0x72, 0xD7, 0x7F, 0x72,
    0xF5, 0x48, 0x4A, 0xF6,
])

def fib_mod(n: int, m: int) -> int:
    """Fast doubling: returns F(n) mod m."""
    def _pair(k: int):
        if k == 0:
            return (0, 1)
        a, b = _pair(k >> 1)       # F(k), F(k+1)
        c = (a * ((2*b - a) % m)) % m
        d = (a*a + b*b) % m
        if k & 1:
            return (d, (c + d) % m)
        else:
            return (c, d)
    return _pair(n)[0] % m

def int_to_be_bytes(x: int) -> bytes:
    """Minimal big-endian bytes (BN_bn2bin semantics)."""
    if x == 0:
        return b"\x00"  # mirrors program's special case allocate(1)=0
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big")

def derive_flag(n: int = 31_333_337) -> bytes:
    # 1) Fibonacci modulo
    v15 = fib_mod(n, M_FIB)

    # 2) modulus = BASE_MOD^4  (BN_exp)
    modulus = pow(BASE_MOD, 4)

    # 3) modular exponent with word base v15 and big exponent EXP
    r = pow(v15, EXP, modulus)

    # 4) multiply by 1337 (BN_mul_word)
    r *= WORD_MUL

    # 5) big-endian minimal serialization
    key = int_to_be_bytes(r)

    # 6) XOR with embedded blob (repeat key)
    out = bytes(BLOB[i] ^ key[i % len(key)] for i in range(len(BLOB)))
    return out

if __name__ == "__main__":
    # Default N is the gate value used by the binary (cmp against 31333337).
    flag = derive_flag(31_333_337)
    try:
        print(flag.decode("ascii"))
    except UnicodeDecodeError:
        # Fallback: show hex if it wasn't clean ASCII
        print(flag.hex())