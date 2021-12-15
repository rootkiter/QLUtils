# QLUtil 概述

QLUtil 是一个基于 qiling 的工具集，其设计目标是从一个 可执行文件( 暂时只支持
ELF类可执行文件)中，选择函数或代码片段，并模拟执行它。

使用它时需要准备两个部分（函数）的代码，第一部分用于控制程序流执行顺序，在这一
部分，你需要组织执行代码的顺序，及执行过程中所需参数等内容，剩下的一部分是
状态回调，在回调中，你可以更新寄存器及内存的数据，或采集你关心的各种数值。
具体的使用细节可以参考[如何使用 章节]。

# 如何安装

## 直接获取源码使用

### Step 1 安装 Qiling。

你需要正确安装 qiling ，这一部分请参考 qiling 的官方文档，这里不再赘述。

### Step 2 获得 QLUtils。

直接将代码下载到你的项目中即可。大致的命令示例如下所示：

```
$ cd [your_project_directory]
$ git clone xxxx/QLUtils.git QLUtils
```

然后你就可以在你的项目中使用它了。

### Step 3 检查是否正确

执行如下命令，如控制台正常输出 "Hello World" 则表明项目无误。否则重复上面的工作
直到正确为止。

```
$ cd [your_project_directory]
$ cp QLUtils/examples/mips_function_emulator.py ./
$ python mips_function_emulator.py
```

执行效果大致如下所示：

```
filekey ->  mips_linux_MSB_libc
[=]	Start      End        Perm    Label          Image
[=]	00400000 - 00404000   r-x     QLUtils/examples/src/sample_bin.mips   QLUtils/examples/src/sample_bin.mips
[=]	00443000 - 00446000   rw-     QLUtils/examples/src/sample_bin.mips   QLUtils/examples/src/sample_bin.mips
[=]	00446000 - 00448000   rwx     [hook_mem]
[=]	7ff0d000 - 7ff3d000   rwx     [stack]
[=]	7ff3d000 - 7ff3e000   rwx     [heap]
None
--->     0 got_patch___stack_chk_guard current_result(got_value_init=2146685132......
--->    20 HELLO                current_result(LABEL='HELLO')......
--->    21 prepare_before       None......
--->     7 dyn_malloc           current_result(arg0=200, ret=2146685556)......
--->     9 dyn_memset           current_result(arg0=2146685556, arg1=0, ......
--->     8 dyn_memcpy           current_result(arg0=2146685556, arg1=420......
--->    21 prepare              current_result(zero=0, at=0, v0=21466855......
--->    21 prepare_done         current_result(zero=0, at=0, v0=21466855......
--->    22 PUSH_POINTER         current_result(PUSH='p_enc # 0x7ff3d274'......
--->    23 decrypt_before       None......
--->    23 decrypt              current_result(zero=0, at=0, v0=21466855......
--->    23 decrypt_done         current_result(zero=0, at=0, v0=21466855......
cnc.changeme.com
---> 99999 EXIT                 current_result(EXIT='Exit')......
Done.
done
None
```

在结果中看到 cnc.changeme.com 的输出，即证明安装成功。

# 如何使用

在 *Step 3* 中使用的 mips\_function\_emulator.py 其实就是一个样例代码，其功能为
从 QLUtils/examples/src/sample\_bin.mips 中，选取两个函数并执行。这个ELF 文件的
源码，可以参考 QLUtils/examples/src/sample\_bin\_source\_code.c，这是一段选自
MIRAI 的源代码。

在 mips\_function\_emulator.py 核心代码仅有如下两段：

```
    gadgets = [
        LABEL("HELLO"),

        arch.CALL_FUNC(
            "prepare", 0x0400310, 0 # , debug=True
        ),
        PUSH_POINTER("p_enc"),
        arch.CALL_FUNC(
            "decrypt", 0x04003B0, 1 # , debug=True
        )
    ]
```

和

```
    if gdt.Alias == "prepare_done":
        rcbnRes.archive("p_enc", curr_res.ret)
    elif gdt.Alias == 'decrypt_done':
        plaintext = qlkit.mem.string(curr_res.ret)
        print(plaintext)
```

第一段代码为执行流控制，第二段代码为和执行流匹配的执行状态控制，及结果读取。
除这两段代码外，其他代码均可理解为默认代码，直接拷贝即可。

并通过 print(plaintext) 将结果打印出来，其输出结果就是 cnc.changeme.com 。


## 简单介绍一下两段代码的细节

第一段为 组织 gadgets ，其中每个 gadget 将完成一个特定的工作，比如一次函数调用
(arch.CALL\_FUNC)，或一次参数准备(PUSH\_xxx)。全部 gadgets 可以参考 Utils/Gadgets 
目录的代码。每个 gadget 有些类似于编写汇编指令。只需要关注执行顺序即可。

示例给出的 gadgets 中描述了先后两次调用子函数的情形：  
第 1 次 CALL\_FUNC 的函数名为prepare， 函数地址 0x0400310，没有参数；
第 2 次 CALL\_FUNC 的函数名为 decrypt，函数地址 0x04003B0, 有1个参数；
由于第 2 次调用需要一个参数，所以执行前需要压栈一个参数供使用，即 PUSH\_POINTER。
其中 p\_enc 的值是在第二段代码中给出的。

第二段代码所属于 callback\_gadgets 函数，在gadgets 中的每一条 gadget 都会至少触发
一次该函数的回调，供 执行/数据状态的控制。所以每次回调中，需要通过 gdt.Alias 判断
本次回调所属于哪一条 gadget 。由于第2次 函数调用参数源于第1次执行的结果，所以当
 prepare\_done 时，获取其执行结果存储于 p\_enc 字段中，供 PUSH\_POINTER 去使用。

curr\_res 参数为每一次gadgets 执行后，能拿到的常用结果。包含寄存器数据和部分
寄存器语义层别名的值。比如第1次函数执行的返回结果的语义别名就是 curr\_res.ret 。
当可执行文件为 mips 时，这个值取自 r0 寄存器，当为 x86 文件时，取自 eax 寄存器等。

rcbnRes 是一个留存中间结果的 key-value 缓存对象，是一个可以在 `gadget / callback
/ Python 代码` 三个层面间传递数据的统一对象，样例代码中已经给出了相应的用法，
请自行参考理解。


