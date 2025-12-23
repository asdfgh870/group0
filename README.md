# hw-shell

## 要求

1. 实现`cd`、`pwd`指令运行
2. Program Execution
3. 解析路径
4. 输入输出重定向

## 开始

我们引入了hw-shell/tokenizer.c/h的库，用来处理用户的输入，完成分割单词的功能。

## 一些必要的函数的介绍

### isatty

`isatty` 函数是一个标准的C库函数，用于检查文件描述符是否引用一个终端设备。换句话说，它可以用来判断一个文件描述符是否与用户的终端（如控制台、终端窗口）相连接。

定义

```
#include <unistd.h> 
int isatty(int fd);
```

参数：`fd`：要检查的文件描述符。例如，`STDIN_FILENO`（标准输入，通常是0）、`STDOUT_FILENO`（标准输出，通常是1）和 `STDERR_FILENO`（标准错误输出，通常是2）。

返回值：如果 `fd` 引用一个终端设备，则返回值为非零（真）。如果 `fd` 不引用一个终端设备，则返回值为0（假），并设置 `errno` 以指示错误。

### getpgrp()

`getpgrp()` 函数是一个标准库函数，用于获取调用进程的进程组 ID。在 Unix 和 Linux 系统中，进程组是用于管理和控制进程集合的机制，尤其是在处理作业控制信号时非常有用。

### tcgetpgrp

`tcgetpgrp` 是一个POSIX标准的库函数，用于获取与终端相关联的前台进程组ID。

### getenv

`getenv` 函数是 C 语言标准库中的一个函数，用于获取指定环境变量的值。环境变量是一些字符串，包含了有关操作系统环境的信息，比如路径、主机名、用户信息等。

### dup2

`dup2` 是一个 POSIX 标准库函数，用于复制文件描述符。它将现有文件描述符复制到一个新的文件描述符，使两个文件描述符指向同一个文件表项。这通常用于重定向输入或输出。

### setpgid

`setpgid(0, 0)` 是一个用于设置进程组ID的函数调用。这是 POSIX 标准中定义的一个函数，目的是改变一个进程的进程组ID。

函数原型

```
#include <unistd.h>

int setpgid(pid_t pid, pid_t pgid);
```

参数

- `pid`：要改变进程组ID的进程的进程ID。如果 `pid` 为 0，则表示调用该函数的进程。
- `pgid`：要将进程移动到的目标进程组ID。如果 `pgid` 为 0，则表示将进程移动到进程ID为 `pid` 的进程组中。

### tcsetpgrp

 `tcsetpgrp` 函数将指定终端的前台进程组设置为调用进程的进程组。

函数原型

```
#include <unistd.h>

int tcsetpgrp(int fd, pid_t pgrp);
```

参数

- `fd`：文件描述符，引用一个终端设备。在这里，它是 `shell_terminal`，表示当前 shell 使用的终端。
- `pgrp`：要设置为前台进程组的进程组 ID。在这里，它是 `getpgrp()` 的返回值，表示当前进程的进程组 ID。



## 实现步骤

### 1.初始化shell环境

1.初始化变量为标准输入描述符shell_terminal = STDIN_FILENO;

2.使用isatty确定是否以交互模式运行

3.确认以交互模式运行时`tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp())`：检查当前进程是否是终端的前台进程组。如果不是，则发送 `SIGTTIN` 信号暂停 shell 进程，直到它成为前台进程。发送暂停信号通过kill传递，

```c
    while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
      kill(-shell_pgid, SIGTTIN);
```

`-shell_pgid`前面的负号（`-`）表示信号将发送给 `shell_pgid` 所指定的进程组中的所有进程。`shell_pgid` 是一个变量，保存着目标进程组的组ID。

`getpid()`：获取当前进程的进程 ID，并保存到 `shell_pgid`。

`tcsetpgrp(shell_terminal, shell_pgid)`：将当前进程组设置为终端的前台进程组。

`tcgetattr(shell_terminal, &shell_tmodes)`：获取当前终端的属性，并保存到 `shell_tmodes`，以便以后可以恢复这些属性。

4.添加需要忽略的信号

```c
  for (int i = 0; i < sizeof(ignore_signals) / sizeof(int); i++)
  {
    signal(ignore_signals[i], SIG_IGN);
  }
```



### 2.打印行号

如果shell 处于可交互模式，打印出行号。

### 3.获取输入

从标准输入中获取4096字节

```c
fgets(line, 4096, stdin)
```

### 4.解析标准输入

使用tokenize库解析标准输入

```
tokenize(line)
```

eg：输入命令cd  /root/

解析完成后tokenize->tokenize[0] 值为cd，tokenize->tokenize[1] 值为/root

### 5.命令执行

判断命令是否是shell的内置命令，cd 、pwd ，执行shell内置命令的处理函数，处理函数都被保存在cmd_table中

```c
typedef struct fun_desc
{
  cmd_fun_t *fun;
  char *cmd;
  char *doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_pwd, "pwd", "print the current working directory"},
    {cmd_cd, "cd", "change the current working directory"},
    {cmd_wait, "wait", "wait for all background processes to finish"}};
```

### 6.实现cd命令

向cmd_table，添加cd命令处理函数。

`cd`有两种情况，一种是带参的，另一种是不带参数的。如cd ~/test
带参数的`cd`会打开对应路径，且只能有一个参数
不带参数的`cd`会打开环境变量`HOME`里存储的路径，若该变量未定义，则不做处理

当没有路径作为参数传入的时候，需要获取环境变量`HOME`的值，使用库函数`getenv`来完成。这个函数定义在`unistd.h`中，使用库函数`chdir()`来更改当前程序的工作目录，同样定义在`unistd.h`中

### 7.实现pwd命令

通过getcwd获取当前路径然后使用printf打印出来。

### 8.实现执行程序

该功能在run_program函数内实现。

shell执行程序的流程如下：

1. 执行fork调用，拷贝一个当前进程的副本
2. 子进程执行exec系列的系统调用，将当前子进程替换成要执行的程序
3. shell等待子进程返回或者让子进程在后台运行（如果有添加`&`参数）

注意有个条件，不允许使用`execvp`调用。

具体操作可以分为以下几步：

1. 解析参数
2. 使用`fork`调用
3. 子进程使用`execv`调用
4. 父进程等待子进程结束

在子进程使用`execv`调用中，设置fork的子进程所属的用户组，将用户调用到前台。将指定信号的处理方式从忽略（`SIG_IGN`）恢复为默认处理（`SIG_DFL`）。具体来说，它遍历一个名为 `ignore_signals` 的数组，并将数组中每个信号的处理方式设置为 `SIG_DFL`。这样，如果这些信号被触发，系统将按照默认方式处理它们。最后执行execv调用程序，如果execv调用失败，则调用 环境变量PATH + 程序名的 execv调用。

### 9.输入输出重定向

在执行程序的时候，第三步，子进程使用`execv`调用中，分析输入的命令，查看是否包含 `>` 和`< `的关键字，获取到后再获取后面紧跟的文件名称。

重定向输入

1.只读方式打开文件，

2.绑定打开文件的套接字，dup2(old_fd, new_fd)

重定向输出

1.create创建文件，

2.绑定创建的文件的套接字，dup2(old_fd, new_fd)

### 10.信号处理

在shell中忽略信号，在shell fork出子进程中使用信号处理。

# pintos-userprog

## 要求

通过所有测试用例

## 开始

userprog的测试用例有很多个，但是可以大致分为5个方面

1.实现参数传递。

2.禁止访问非法内存

3.实现系统调用

4.实现浮点指令可用。

5.实现无内存泄漏。

## 1.实现参数传递

操作系统执行用户程序的调用栈如下所示

> main()
>
> > ```
> >   if (*argv != NULL) {
> >     /* Run actions specified on kernel command line. */
> >     run_actions (argv);
> >   }
> > ```
> >
> > > static void run_task(char** argv)
> > >
> > > > pid_t process_execute(const char* proc_cmd_) 

参数传递到process_execute仍然是完整的 如 do-noting xx xx，等。

通过申请一片内存存放proc_cmd_，传递给线程的执行函数start_process。

我们需要解析start_process中cmd_的参数，创建中断调用的结构体，

```
struct intr_frame if_;
```

指定if_.esp初始值为0xc0000000，按调用用户态程序的堆栈摆放顺序那样从0xc0000000填入内容就可以了，同时注意维护好if_esp的值，摆放顺序参考了[3. Project 2: User Programs - Pintos Docs (etao.net)](https://docs.etao.net/pintos_3/#335-denying-writes-to-executables)

如下所述：

### 程序启动详情[#](https://docs.etao.net/pintos_3/#351)

用户程序的Pintos C库在“`lib/user/entry.c`”中指定“_start()”作为用户程序的入口点。此函数是`main()`的包装，如果main()返回以下内容，则调用`exit()`：

```cpp
void
_start (int argc, char *argv[]) 
{
  exit (main (argc, argv));
}
```

在允许用户程序开始执行之前，内核必须将初始函数的参数放在堆栈上。 参数的传递方式与常规调用约定相同（请参见[3.5 80x86调用约定](https://docs.etao.net/pintos_3/#35-80x86调用约定)）。

考虑如何处理以下示例命令的参数：“/bin/ls -l foo bar”。首先，将命令分解为单词：“/bin /ls”，“-l”，“foo”，“bar”。 将单词放在堆栈的顶部。 顺序无关紧要，因为它们将通过指针进行引用。

然后，按从右到左的顺序将每个字符串的地址以及一个空指针哨兵压入堆栈。这些是“argv”的元素。空指针sendinel可以确保C标准所要求的argv[argc]是空指针。该命令确保“argv[0]”位于最低虚拟地址。字对齐的访问比未对齐的访问要快，因此为了获得最佳性能，在第一次压入之前将堆栈指针向下舍入为4的倍数。

然后，依次按“argv”（“argv[0]”的地址）和“argc”。最后，推送一个伪造的“返回地址”：尽管入口函数将永远不会返回，但其堆栈框架必须具有与其他任何结构相同的结构。

下表显示了在用户程序开始之前堆栈的状态以及相关的寄存器，假设PHYS_BASE为“0xc0000000”：

| Address    | Name           | Data        | Type        |
| ---------- | -------------- | ----------- | ----------- |
| 0xbffffffc | argv[3][...]   | “bar\0”     | char[4]     |
| 0xbffffff8 | argv[2][...]   | “foo\0”     | char[4]     |
| 0xbffffff5 | argv[1][...]   | “-l\0”      | char[3]     |
| 0xbfffffed | argv[0][...]   | "/bin/ls\0” | char[8]     |
| 0xbfffffec | word-align     | 0           | uint8_t     |
| 0xbfffffe8 | argv[4]        | 0           | char *      |
| 0xbfffffe4 | argv[3]        | 0xbffffffc  | char *      |
| 0xbfffffe0 | argv[2]        | 0xbffffff8  | char *      |
| 0xbfffffdc | argv[1]        | 0xbffffff5  | char *      |
| 0xbfffffd8 | argv[0]        | 0xbfffffed  | char *      |
| 0xbfffffd4 | argv           | 0xbfffffd8  | char **     |
| 0xbfffffd0 | argc           | 4           | int         |
| 0xbfffffcc | return address | 0           | void (*) () |

在这个例子中，堆栈指针将被初始化为0xbfffffcc。

如上所示，您的代码应在用户虚拟地址空间的最顶部，即虚拟地址“PHYS_BASE”（在“threads/vaddr.h”中定义）下方的页面中开始堆栈。

您可能会发现在“”中声明的非标准`hex_dump()`函数对于调试参数传递代码很有用。在上面的示例中将显示以下内容：

```bash
bfffffc0                                      00 00 00 00 |            ....|
bfffffd0  04 00 00 00 d8 ff ff bf-ed ff ff bf f5 ff ff bf |................|
bfffffe0  f8 ff ff bf fc ff ff bf-00 00 00 00 00 2f 62 69 |............./bi|
bffffff0  6e 2f 6c 73 00 2d 6c 00-66 6f 6f 00 62 61 72 00 |n/ls.-l.foo.bar.|
```

## 2.禁止访问非法内存

作为系统调用的一部分，内核必须经常通过用户程序提供的指针访问内存。内核必须非常小心，因为用户可能传递一个空指针，一个指向未映射虚拟内存的指针或一个指向内核虚拟地址空间的指针（在PHYS_BASE之上）。必须通过终止有问题的进程并释放其资源，拒绝所有这些类型的无效指针，而不会损害内核或其他正在运行的进程。

方法是仅检查用户指针是否指向“PHYS_BASE”下方，然后解引用。无效的用户指针将导致“页面错误”，您可以通过修改“userprog/exception.c”中的“page_fault()”的代码来处理。该技术通常更快，因为它利用了处理器的MMU,因此倾向于在实际内核（包括Linux）中使用。

参考文档中提供了一些访问内存的代码

```
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
```

我对以上代码封装，完成了读写检查

check_user_addr_can_read/wite,

```
// uaddr类型要指定void，不能是uint32_t,设置为uint32_t在+1的时候会直接+4
void* check_user_addr_can_read(const void *uaddr,size_t size) {
  if (!is_user_vaddr(uaddr)) {
    process_terminate();
  }
  for(int i=0;i<size;i++) {
    if(get_user(uaddr+i)== -1) {
      process_terminate(); 
    }
  }
  return (void *)uaddr;
}

void* check_user_addr_can_write(const void *uaddr,size_t size) {
  if (!is_user_vaddr(uaddr)) {
    process_terminate();
  }
  for(int i=0;i<size;i++) {
    if(!put_user(uaddr,0)) {
      int exit_code;
      asm volatile ("mov %%eax, %0" : "=g"(exit_code));
      process_terminate(); 
    }
  }
  return (void *)uaddr;
}
```

还创建了一个专门检查字符串是否可读的函数check_str_can_read

```
void* check_str_can_read(const uint32_t *uaddr)
{
    if (!is_user_vaddr(uaddr)) {
    process_terminate();
  }
  for(int i=0;;i++) {
    if(get_user(uaddr+i) == -1) {
      process_terminate(); 
    } else if(*(char*)(uaddr+i) == '\0') {
      break;
    }
  }
  return (void *)uaddr;
}
```

## 3.系统调用

这部分内容的框架都由pintos提供了，我们只需要不断向syscall_handler中添加系统调用的处理函数即可，注意访问内存前检查和将返回结果填入intr_frame的eax字段。

## 4.实现浮点指令可用

### FPU介绍

最初，FPU 是一个放置在实际处理器顶部的专用协处理器芯片。由于它以异步方式执行计算，其结果会在主处理器执行几条其他指令后可用。由于错误也会异步出现，原始 PC 将 FPU 的错误线连接到中断控制器。当 486 添加多处理器支持后，变得不可能检测哪个 FPU 引发了异常，因此他们将 FPU 集成到芯片内并添加了一个选项，用于发出常规异常而不是中断。为了提供向后兼容性，486 配备了一个引脚来替代原始的 FPU 错误线，该引脚将连接到 PIC 然后返回到 CPU 的 IRQ 线，以模拟带有专用协处理器的原始设置。结果是默认情况下，浮点异常不会按手册推荐的方式操作。

### 检查 FPU 支持

在 x86 处理器上，直到 386，FPU 都是外部的，并且是严格可选的。它们允许使用不同的浮点单元，包括那些不严格对应处理器生成的浮点单元。例如，386 可以同时使用 287(与 286 对应的 FPU) 和 387(当代的FPU)。486 系列微处理器分为 486DX 和 486SX，前者包含一个片上浮点单元，后者不包含浮点单元。外部 487 协处理器本质上是一个修改后的 486DX，它禁用了安装的 CPU。从奔腾开始的所有x86 CPU 都有一个集成的 FPU(不包括 NexGen 5x86)。

检测 FPU 有两种方法:

- 检查 CPUID 中的 FPU 位；
- 检查 CR0 中的 EM 位，如果它被设置，那么 FPU 不应该被使用；
- 检查 CR0 中的 ET 位，如果它被清除，那么 CPU 在引导时没有检测到 80387；
- 探测 FPU；

正确的顺序有点可疑。当前的官方手册指出，当 FPU 不存在时，尝试使用 FPU 会锁住 CPU。然而，有许多源代码包含不同复杂程度的探测代码，人们普遍认为不执行 fwait 或实际计算。类似地，EM 和 ET 位可以通过代码修改，并且可能没有正确的值。实际硬件上的不同连线也可能导致 386 没有将 FPU 检测为 80386，导致 ET 位在引导时具有错误的值。

测试 FPU 是否存在的常见方法是让它在某个地方写状态，然后检查它是否真的写了。

要区分 287 和 387 FPU，您可以尝试它是否可以看到 $+\infty$ 和 $-\infty$ 之间的差异。

### FPU 控制

如果发现存在 FPU，则应相应地设置控制寄存器。如果 FPU 不存在，也应该相应地设置寄存器。

- CR0.EM (bit 2) (**EM**ulated)

    如果设置了 EM 位，所有 FPU 和向量操作都将导致 #NM，因此它们可以在软件中模拟。清除 EM 位才能使用 FPU；

- CR0.ET (bit 4)

    这个位在 386 上用于告诉它如何与协处理器通信，对于287 是 0，对于 387 或更高版本是 1，这个位是硬连接在 486+ 上的

- CR0.NE (bit 5)

    当设置时，启用本地异常处理，将使用 FPU 异常。当被清除时，通过中断控制器发送一个异常。486+ 应该有，但 386 没有；

- CR0.TS (bit 3)

    任务切换。FPU 状态被设计为延迟切换，以节省读写周期。如果设置，所有有意义的操作都会导致 #NM 异常，以便 OS 备份 FPU 状态。该位在硬件任务开关上自动设置，可以使用 CLTS 操作码清除。如果软件任务切换想要延迟存储 FPU 状态，可能需要手动设置这个位重新调度。

- CR0.MP (bit 1)

    除了说明 FWAIT 操作码是否免于响应 TS 位外，它几乎没有其他作用。由于 FWAIT 将强制异常序列化，它通常应该设置为 EM 位取反，因此 FWAIT 实际上会在FPU 指令是异步的时候引起 FPU 状态更新，而不是在它们被模拟的时候；

- CR4.OSFXSR (bit 9)

    启用 128 位 SSE 支持。当清除时，大多数 SSE 指令将导致无效的操作码，FXSAVE 和 FXRSTOR 将只包括原始的 FPU 状态。设置后，SSE 是允许的，XMM 和 MXCSR 寄存器是可访问的，这也意味着您的操作系统应该维护那些额外的寄存器。尝试在没有 SSE 的 CPU 上设置此位将导致异常，因此您应该首先检查 SSE(或长模式)支持。

- CR4.OSXMMEXPT (bit 10)

    启用 #XF 异常。当清除时，SSE 将一直工作，直到生成一个异常，之后所有 SSE 指令都将失败，操作码无效。设置后，将调用异常处理程序，并且可以诊断和报告问题。同样，在没有确保 SSE 支持的情况下，您不能设置此位

- CR4.OSXSAVE (bit 18)

    启用 XSAVE 扩展，它能够保存 SSE 状态以及其他下一代寄存器状态。再次，在设置之前检查 CPUID 在这种情况下长模式支持是不够的。

### pintos中的fpu使用

当前代码中没有实现fpu检查，直接开始使用了。设计了一些fpu相关的工具函数，和线程中的相关字段。

工具函数

```c
enum
{
   CR0_EM = 1 << 2,  // Emulation 启用模拟，表示没有 FPU
   CR0_TS = 1 << 3,  // Task Switch 任务切换，延迟保存浮点环境
};

uint32_t get_cr0()
{
   // 直接将 mov eax, cr0，返回值在 eax 中
   asm volatile("movl %cr0, %eax\n");
};

// 设置 cr0 寄存器，参数是页目录的地址
void set_cr0(uint32_t cr0)
{
   asm volatile("movl %%eax, %%cr0\n" ::"a"(cr0));
}

// 禁用FPU
void fpu_disable()
{
  set_cr0(get_cr0() | (CR0_EM | CR0_TS));
}

void fpu_enable(){
  set_cr0(get_cr0() & ~(CR0_EM | CR0_TS));
}
```

相关字段，这个字段位于thread结构体中，

```
  bool fpu_flag; // 是否使用过fpu
  fpu_t* fpu_state;
  
fpu_t定义如下
typedef struct fpu_t
{
    uint16_t control;
    uint16_t RESERVED1;
    uint16_t status;
    uint16_t RESERVED2;
    uint16_t tag;
    uint16_t RESERVED3;
    uint32_t fip0;
    uint32_t fop0;
    uint32_t fdp0;
    uint32_t fdp1;
    char regs[80];
}fpu_t;
```

注意fpu_t是108个字节，用来存储fsave的108字节大小的寄存器内容。

fpu使用方式如下。

系统刚启动时，fpu默认不可用，当系统执行fpu相关指令时，触发缺少设备异常，异常号为0x07。执行处理函数intr_no_fpu，在intr_no_fpu，执行以下操作：

1.开启fpu，

2，检查这个线程之前是否使用过fpu，如果使用过，恢复浮点环境到线程字段中，没使用过则执行首次初始化。

注意存在线程切换，我们需要在切换线程时保存fpu状态，并关闭fpu，这段代码体现在schedule()中

```c
static void schedule(void) {
  struct thread* cur = running_thread();
  struct thread* next = next_thread_to_run();
  struct thread* prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  if (cur != next) {
    if(cur->fpu_flag == true) {
      asm volatile("fnsave (%%eax) \n" ::"a"(cur->fpu_state));
      fpu_disable();
    }
    prev = switch_threads(cur, next);
  }
  thread_switch_tail(prev);
}
```

## 5.无内存泄漏

主要针对mutli-oom测试用例，这个用例用来不断申请内存，至少要能申请10个循环。所以要及时释放内存，需要检查代码中malloc和palloc_get_page的使用有没有没有释放的。尤其是palloc_get_page，申请内存很多。