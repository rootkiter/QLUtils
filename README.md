# QLUtil 概述

QLUtil 是一个基于 qiling 的工具集，其设计目标是从一个 可执行文件( 暂时只支持
ELF类可执行文件)中，选择函数或代码片段，并模拟执行它。

使用它时需要准备两个部分（函数）的代码，第一部分用于控制程序流执行顺序，在这一
部分，你需要组织执行代码的顺序，及执行过程中所需参数等内容，剩下的一部分是
状态回调，在回调中，你可以更新寄存器及内存的数据，或采集你关心的各种数值。
具体的使用细节可以参考[How To Use 章节]。

# 如何安装

## 直接获取源码使用

### Step 1 安装 Qiling。

你需要正确安装 qiling ，这一部分请参考 qiling 的官方文档，这里不再赘述。

### Step 2 获得 QLUtils。

直接将代码下载到你的项目中即可。大致的命令示例如下所示：

```
$ cd [your\_project\_directory]
$ git clone xxxx/QLUtils.git QLUtils
```

然后你就可以在你的项目中使用它了。

### Step 3 检查是否正确

执行如下命令，如控制台正常输出 "Hello World" 则表明项目无误。否则重复上面的工作
直到正确为止。

```
$ cd [your\_project\_directory]
$ cp QLUtils/examples/helloworld\_mips.py ./
$ python helloworld\_mips.py
```

执行效果大致如下所示：

```
filekey ->  mips\_linux\_MSB\_libc
[=]	Start      End        Perm    Label          Image
[=]	00400000 - 00404000   r-x     QLUtils/examples/src/sample\_bin.mips   QLUtils/examples/src/sample\_bin.mips
[=]	00443000 - 00446000   rw-     QLUtils/examples/src/sample\_bin.mips   QLUtils/examples/src/sample\_bin.mips
[=]	00446000 - 00448000   rwx     [hook\_mem]
[=]	7ff0d000 - 7ff3d000   rwx     [stack]
[=]	7ff3d000 - 7ff3e000   rwx     [heap]
None
--->     0 got\_patch\_\_\_stack\_chk\_guard current\_result(got\_value\_init=2146685132......
--->    20 HELLO                current\_result(LABEL='HELLO')......
--->    21 prepare\_before       None......
--->     7 dyn\_malloc           current\_result(arg0=200, ret=2146685556)......
--->     9 dyn\_memset           current\_result(arg0=2146685556, arg1=0, ......
--->     8 dyn\_memcpy           current\_result(arg0=2146685556, arg1=420......
--->    21 prepare              current\_result(zero=0, at=0, v0=21466855......
--->    21 prepare\_done         current\_result(zero=0, at=0, v0=21466855......
--->    22 PUSH\_POINTER         current\_result(PUSH='p\_enc # 0x7ff3d274'......
--->    23 decrypt\_before       None......
--->    23 decrypt              current\_result(zero=0, at=0, v0=21466855......
--->    23 decrypt\_done         current\_result(zero=0, at=0, v0=21466855......
cnc.changeme.com
---> 99999 EXIT                 current\_result(EXIT='Exit')......
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
        rcbnArchive.archive("p_enc", curr_res.ret)
    elif gdt.Alias == 'decrypt_done':
        plaintext = qlkit.mem.string(curr_res.ret)
        print(plaintext)
```

第一段代码为执行流控制，第二段代码为和执行流匹配的执行状态控制，及结果读取。

并通过 print(plaintext) 将结果打印出来，其输出结果就是 cnc.changeme.com 。


