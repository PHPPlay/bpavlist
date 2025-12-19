## 从C项目到汇编，再到Shellcode  
v 1.2  
作者：hasherezade for @vxunderground  
_特别感谢Duchy的测试_

---

### 目录

1. 引言 2  
2. 前期工作与动机 2  
3. Shellcode - 一般原则 3  
   - 位置无关代码 3  
   - 不使用导入表调用API 4  
4. 总结：头文件 9  
5. 编写和编译汇编代码 12  
6. 编译C项目 - 逐步指南 14  
7. 从C项目到Shellcode 16  
   - 核心思想 16  
   - 准备C项目 16  
   - 重构汇编代码 24  
8. 扩展示例 - 演示服务器 29  
   - 构建 34  
   - 运行 34  
   - 测试 34  
9. 结论 35  

---

### 引言

恶意软件作者（以及漏洞利用开发者）经常在他们的工作中使用独立的、位置无关的代码片段，称为Shellcode。这种类型的代码可以轻松地注入到内存中的任何合适位置，并立即执行，而无需外部加载器。尽管Shellcode为研究人员（和恶意软件作者）提供了许多优势，但编写它却非常繁琐。Shellcode必须遵循与编译器通常输出的格式非常不同的原则。这就是为什么人们通常使用汇编语言编写Shellcode，以便完全控制生成的输出格式。

虽然用汇编语言编写Shellcode是最可靠和最准确的方式，但它既繁琐又容易出错。因此，许多研究人员提出了简化整个过程的想法，并利用C编译器而不是手工编写完整的Shellcode。在本文中，我将分享我的经验以及我用于这些目的的方法。

本文旨在对初学者友好，因此我详细描述了一些众所周知的、通用的Shellcode创建技术。在前几段中，我展示了一些Shellcode需要遵循的一般原则，并解释了所提出方法背后的原因。然后，我提供了逐步的指导和示例，帮助创建Shellcode。

通过本文介绍的方法，我们可以避免完全手工编写汇编代码，同时仍然能够方便地编辑生成的汇编代码。我们不会失去手工编写Shellcode的优势，但跳过了繁琐的部分。

---

### 前期工作与动机

从C代码创建Shellcode的想法并不新鲜。

在2012年出版的《The Rootkit Arsenal - Second Edition》中，Bill Blunden解释了从C代码创建Shellcode的方法（第10章：用C语言构建Shellcode）。类似的方法由Matt Graeber（Mattifestation）在他的文章《Writing Optimized Windows Shellcode in C》中描述。在这两种情况下，Shellcode都是直接从C代码创建的，整个想法与更改编译器设置有关，以便创建一个PE文件，从中我们可以提取独立代码的缓冲区。

然而，在这些方法中，我缺少的是从头开始用纯汇编编写的Shellcode的优势。在上述情况下，我们只能得到最终的代码，但无法直接控制生成的汇编代码，也没有机会对其进行修改或交互。

我一直在寻找一种方法，能够结合两者的优点：允许跳过编写汇编的繁琐且容易出错的部分，同时生成我可以自由修改的汇编代码，并最终用于生成我的Shellcode。

---

### Shellcode - 一般原则

在PE格式的情况下，我们只需编写代码，而不必担心它如何加载：Windows加载程序会处理它。当我们编写Shellcode时，情况就不同了。我们不能依赖PE格式和Windows加载程序提供的便利：

- 没有节区  
- 没有数据目录（导入、重定位）  

我们只有代码来提供我们所需的一切...

以下是PE文件和Shellcode之间的一些重要区别的概述：

| 特性                    | PE文件                                                     | Shellcode                                                    |
| ----------------------- | ---------------------------------------------------------- | ------------------------------------------------------------ |
| 加载                    | 通过Windows加载程序；运行新的EXE会触发新进程的创建         | 自定义的简化加载；必须寄生在现有进程上（例如通过代码注入+线程注入），或附加到现有的PE上（例如病毒） |
| 组成                    | 具有特定访问权限的节区，携带各种元素（代码、数据、资源等） | 所有内容都在一个内存区域中（读、写、执行）                   |
| 重定位到加载基址        | 由重定位表定义，由Windows加载程序应用                      | 自定义；位置无关代码                                         |
| 访问系统API（导入加载） | 由导入表定义，由Windows加载程序应用                        | 自定义：通过PEB查找检索导入；没有IAT，或简化                 |

---

### 位置无关代码

在PE文件的情况下，我们有一个重定位表，Windows加载程序使用它来根据内存中加载的可执行文件的基址调整所有地址。这是在运行时自动完成的。

在Shellcode的情况下，我们不能利用这个功能——因此我们需要编写代码，使其不需要重定位。遵循这些原则的代码称为位置无关代码（PIC）。

我们通过仅使用相对于当前指令指针的地址来创建位置无关代码。我们可以使用短跳转、长跳转、调用本地函数，因为它们都是相对的。

假设作为创建Shellcode的步骤之一，我们将创建一个PE文件，其完整的代码节是位置无关代码。为了实现这一点，我们不能使用引用其他PE节区数据的任何地址。如果我们想使用任何字符串或其他数据，我们必须将其内联到代码中。

---

### 不使用导入表调用API

在PE的情况下，我们在代码中引用的所有API调用都将被收集到导入表中。导入表的创建由链接器完成。然后，导入表的解析在运行时完成。所有这些都是默认处理的。

在Shellcode的情况下，我们不能再访问导入表，因此我们需要自己负责解析API。

为了检索我们在Shellcode中使用的API函数，我们将利用PEB（进程环境块——在进程运行时创建的系统结构之一）。一旦我们的Shellcode被注入到进程中，我们将检索目标的PEB，然后使用它来搜索加载到进程地址空间中的DLL。我们获取Ntdll.dll或Kernel32.dll以解析其余的导入。Ntdll.dll在每个进程的早期阶段加载。Kernel32.dll在大多数进程初始化后加载——因此我们可以安全地假设它将在我们感兴趣的进程中加载。一旦我们检索到其中任何一个，我们就可以使用它来加载其他所需的DLL。

检索Shellcode导入的概述：

1. 获取PEB地址  
2. 通过PEB->Ldr->InMemoryOrderModuleList，找到：  
   - kernel32.dll（在大多数进程中默认加载）  
   - 或ntdll.dll（如果我们想使用导入加载函数的低级等效项）  
3. 遍历kernel32（或ntdll）的导出表，找到以下地址：  
   - kernel32.LoadLibraryA（最终：ntdll.LdrLoadDll）  
   - kernel32.GetProcAddress（最终：ntdll.LdrGetProcedureAddress）  
4. 使用LoadLibraryA（或LdrLoadDll）加载所需的DLL  
5. 使用GetProcAddress（或LdrGetProcedureAddress）检索所需的函数  

---

### 检索PEB

幸运的是，PEB可以通过纯汇编轻松检索。PEB的指针是另一个结构体TEB（线程环境块）的字段之一。

```c
typedef struct TEB {
    PVOID Reserved1[12];
    PPEB ProcessEnvironmentBlock;
    PVOID Reserved2[39];
    BYTE Reserved3[1952];
    PVOID TlsSlots[64];
    PVOID Reserved5[26];
    PVOID ReservedForOle;
    PVOID Reserved6[4];
    PVOID TlsExpansionSlots;
} TEB, *PTEB;

typedef struct PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG ImageUsesLargePages:1;
    ULONG IsProtectedProcess:1;
    ULONG IsLegacyProcess:1;
    ULONG IsImageDynamicallyRelocated:1;
    ULONG SpareBits:4;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // [...] 更多字段
} PEB, *PPEB;
```

TEB由段寄存器指向：在32位进程的情况下是FS寄存器，在64位进程的情况下是GS寄存器。

```c
进程位数 | 32位 | 64位  
指向TEB的指针 | FS寄存器 | GS寄存器  
从TEB到PEB的偏移量 | 0x30 | 0x60
```

为了从汇编中获取PEB，我们只需从指向TEB的段寄存器中获取特定偏移量的字段。如果我们在C中实现它，它看起来像这样：

```c
PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)_readgsqword(0x60);
#else
    peb = (PPEB)_readfsdword(0x30);
#endif
```

---

### 基于PEB的DLL查找

PEB的一个字段是加载到进程内存中的所有DLL的链表：

```c
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

我们将遍历此列表，直到找到我们正在寻找的DLL。

此时，我们需要一个DLL来帮助我们解析我们想要导入的其他API。我们可以使用Kernel32.dll（或最终使用Ntdll.dll，但Kernel32更方便）。

通过DLL查找检索具有选定名称的DLL的整个过程在以下C代码中演示：

```c
#include <Windows.h>

#ifndef __NTDLL_H__
#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a' : c1)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    HANDLE SectionHandle;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // [...] 更多字段
} PEB, *PPEB;

#endif //__NTDLL_H__

inline LPVOID get_module_by_name(WCHAR* module_name) {
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)_readgsqword(0x60);
#else
    peb = (PPEB)_readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY curr_module = Flink;

    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (curr_module->BaseDllName.Buffer == NULL) continue;
        WCHAR* curr_name = curr_module->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        if (module_name[i] == 0 && curr_name[i] == 0) {
            // 找到
            return curr_module->BaseAddress;
        }
        // 未找到，尝试下一个
        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}
```

---

### 导出查找

一旦我们检索到Kernel32.dll的基址，我们仍然需要检索所需函数的地址：LoadLibraryA和GetProcAddress。我们将通过导出查找来完成。

首先，我们需要从找到的DLL的数据目录中获取导出表。然后，我们遍历所有按名称导出的函数，直到找到我们感兴趣的名称。我们获取与该名称关联的RVA，并添加模块基址，以获得绝对地址（VA）。

导出查找函数：

```c
inline LPVOID get_func_by_name(LPVOID module, char* func_name) {
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    // 遍历名称
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k = 0;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            // 找到
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}
```

---

### 总结：头文件

我们将上述所有代码收集到一个头文件`peb_lookup.h`中（可在此处获取），我们可以将其包含到我们的项目中，以便使用PEB查找。

```c
#pragma once
#include <Windows.h>

#ifndef __NTDLL_H__
#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a' : c1)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    HANDLE SectionHandle;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // [...] 更多字段
} PEB, *PPEB;

#endif //__NTDLL_H__

inline LPVOID get_module_by_name(WCHAR* module_name) {
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)_readgsqword(0x60);
#else
    peb = (PPEB)_readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY curr_module = Flink;

    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (curr_module->BaseDllName.Buffer == NULL) continue;
        WCHAR* curr_name = curr_module->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        if (module_name[i] == 0 && curr_name[i] == 0) {
            // 找到
            return curr_module->BaseAddress;
        }
        // 未找到，尝试下一个
        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

inline LPVOID get_func_by_name(LPVOID module, char* func_name) {
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    // 遍历名称
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k = 0;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            // 找到
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}
```

---

### 编写和编译汇编代码

如前所述，编写Shellcode的典型方法是使用汇编语言。

当我们编写汇编代码时，首先必须选择我们想要用来编译代码的汇编器。这个选择对我们必须使用的语法施加了一些细微的差异。

Windows上最流行的汇编器是**MASM**——它是Visual Studio的一部分，有两个版本：32位（ml.exe）和64位（ml64.exe）。MASM生成的输出是一个对象文件，可以链接到PE。假设我们有一个用32位MASM编写的简单示例，显示一个消息框：

```asm
.386
.model flat

extern _MessageBoxA@16:near
extern _ExitProcess@4:near

.data
msg_title db "Demo1", 0
msg_content db "Hello World!", 0

.code
main proc
    push    0
    push    0
    push    offset msg_title
    push    offset msg_content
    push    0
    call    _MessageBoxA@16
    push    0
    call    _ExitProcess@4
main endp
end
```

我们将通过以下命令编译此代码：

```bash
ml /c demo32.asm
```

然后我们可以使用默认的Visual Studio链接器链接它：

```bash
link demo32.obj /subsystem:console /defaultlib:kernel32.lib /defaultlib:user32.lib /entry:main /out:demo32_masm.exe
```

有时我们也可以一步完成编译和链接，只需使用以下命令：

```bash
ml demo32.asm
```

MASM是Windows的默认汇编器。然而，创建Shellcode的最流行选择是另一个汇编器：YASM（NASM的继任者）。它是一个免费的、独立的汇编器，适用于多个平台。它可以像MASM一样用于创建PE文件。YASM的语法略有不同。假设我们有一个用32位YASM编写的类似示例：

```asm
bits 32

extern _MessageBoxA@16:proc
extern _ExitProcess@4:proc

msg_title db "Demo1", 0
msg_content db "Hello World!", 0

global main

main:
    push 0
    push 0
    push msg_title
    push msg_content
    push 0
    call _MessageBoxA@16
    push 0
    call _ExitProcess@4
```

我们可以通过以下命令编译它：

```bash
yasm -f win32 demo32.asm -o demo32.obj
```

然后，类似于MASM代码，我们可以使用Visual Studio链接器（或我们选择的任何其他链接器）链接它：

```bash
link demo32.obj /defaultlib:user32.lib /defaultlib:kernel32.lib /subsystem:windows /entry:main /out:demo32_yasm.exe
```

与MASM不同，YASM还可以用于将代码编译为二进制文件，而不是对象文件。因此，我们可以获得一个可以直接使用的二进制缓冲区作为Shellcode。编译为二进制文件的示例：

```bash
yasm -f bin demo.asm
```

_请注意，上述示例都不能编译为Shellcode，因为它们具有外部依赖项——因此它们不遵循Shellcode原则。但我们可以通过删除依赖项来重构它们为Shellcode。_

**本文介绍的方法使用MASM。选择它的原因很简单：如果我们使用Visual Studio C编译器从C文件生成汇编代码，结果将是MASM语法。与YASM不同，我们不能直接设置它输出Shellcode：我们需要手动从PE中提取代码。正如我们将看到的，尽管这似乎是一个小不便，但它有其优点，例如简化测试。**

---

### 编译C项目 - 逐步指南

如今，大多数人使用集成环境（如Visual Studio）编译他们的代码，这些环境隐藏了编译过程的复杂性。我们只需编写代码，然后一步编译和链接。默认情况下，最终结果是一个PE文件：Windows的原生可执行格式。

然而，有时将此过程分解为步骤是有用的，这样我们可以更好地控制它。

让我们回顾一下C/C++代码的编译过程在概念上的样子：

```
MyApp.exe
Native code

MyApp.cpp
MyApp.h MyApp.obj Used_library.lib

preprocess
compile assemble link
```

现在将其与从汇编代码创建应用程序的步骤进行比较：

```
MyApp.inc MyApp.obj Used_library.lib

MyApp.asm MyApp.exe

preprocess assemble link Native code
```

正如我们所看到的，从高级语言编译代码的差异仅在于开始阶段。此外，在编译C代码时，其中一个步骤会生成汇编代码。这很有趣，因为我们可以用C编写代码，然后要求编译器将汇编代码作为输出。然后，我们只需根据Shellcode原则修改汇编代码。更多内容将在后续段落中解释。

我们有以下示例代码：

```c
#include <Windows.h>

int main() {
    const char msg_title[] = "Demo!";
    const char msg_content[] = "Hello World!";

    MessageBoxA(0, msg_title, msg_content, MB_OK);
    ExitProcess(0);
}
```

让我们尝试使用Visual Studio编译器和链接器从命令提示符编译此代码，而不是使用集成环境。我们可以通过选择“VS Native Tools Command Prompt”来完成此操作。然后我们需要导航到包含我们代码的目录。

输出可执行文件的位数（32位或64位）将根据您选择的命令提示符版本默认选择。

要编译代码，我们使用cl.exe。使用选项`/c`编译代码但阻止链接它：因此，结果我们得到一个对象文件（*.obj）。

```bash
cl /c demo.cpp
```

然后，我们可以使用Visual Studio包中的默认链接器link.exe链接obj文件。有时我们需要提供必须与应用程序链接的附加库，或入口点（如果它使用与默认标签不同的标签）。链接的示例：

```bash
link demo.obj /defaultlib:user32.lib /out:demo_cpp.exe
```

_请注意，由于这些步骤彼此独立，您也可以使用替代链接器而不是默认链接器——这也可以用于操作或混淆格式。一个很好的例子是crinkler，它是一个以链接器形式存在的可执行文件压缩器。但这是另一个故事..._

如果添加参数`/FA`，除了*.obj文件外，您还将获得MASM格式的汇编输出。

```bash
cl /c /FA demo.cpp
```

然后，您可以使用MASM将生成的汇编代码编译为对象文件：

```bash
ml /c demo.asm
```

将此过程分解为步骤使我们能够操作汇编代码，并根据我们的需求进行调整，而不是从头开始编写它。

---

### 从C项目到Shellcode

#### 核心思想

本文介绍的创建Shellcode的方法利用了我们可以将C代码编译为汇编代码的事实。它由以下基本步骤组成：

1. 准备一个C项目。  
2. 重构项目以通过PEB查找加载所有使用的导入（删除对导入表的依赖）。  
3. 使用C编译器生成汇编代码：  
   ```bash
   cl /c /FA /GS- <file_name>.cpp
   ```
4. 重构汇编代码以使其成为有效的Shellcode（删除其他剩余的依赖项，内联字符串、变量等）。  
5. 使用MASM编译它：  
   ```bash
   ml /c file.asm
   ```
6. 将其链接为有效的PE文件，测试其是否正常运行。  
7. 转储代码节（例如使用PE-bear）——这就是我们的Shellcode。

_请注意，C编译器生成的汇编代码并不保证始终是100%有效的MASM代码，因为它主要是作为信息性列表生成的。因此，有时需要手动清理。_

#### 准备C项目

当我们准备一个C项目以编译为Shellcode时，我们需要遵循一些规则：  
- 不要直接使用导入——始终通过PEB动态解析它们。  
- 不要使用任何静态库。  
- 仅使用局部变量：没有全局变量，没有静态变量（否则它们将存储在单独的节中并破坏位置独立性！）。  
- 使用基于栈的字符串（或稍后在汇编中内联它们）。

作为示例，我们将使用一个简单的演示，弹出一个消息框：

```c
#include <Windows.h>

int main() {
    MessageBoxA(0, L"Hello World!", L"Demo!", MB_OK);
    ExitProcess(0);
}
```

#### 准备导入

作为我们准备的第一步，我们需要使所有使用的导入动态加载。在这个项目中有两个导入：来自user32.dll的MessageBoxA和来自kernel32.dll的ExitProcess。

在正常情况下，如果我们希望这些导入动态加载，而不是包含在导入表中，我们将重构它，类似于以下内容：

```c
#include <Windows.h>

int main() {
    LPVOID u32_dll = LoadLibraryA("user32.dll");

    int (WINAPI * _MessageBoxA)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) = (int (WINAPI*)(
        _In_opt_ HWND,
        _In_opt_ LPCWSTR,
        _In_opt_ LPCWSTR,
        _In_ UINT)) GetProcAddress((HMODULE)u32_dll, "MessageBoxA");

    if (_MessageBoxA == NULL) return 4;

    _MessageBoxA(0, L"Hello World!", L"Demo!", MB_OK);

    return 0;
}
```

这是准备的第一步，但还不够：我们仍然有两个依赖项：LoadLibraryA和GetProcAddress。这两个函数我们需要通过PEB查找来解析——我们将使用我们在前一部分创建的`peb_lookup.h`。这是重构的最终结果`popup.cpp`：

```c
#include <Windows.h>
#include "peb_lookup.h"

int main() {
    LPVOID base = get_module_by_name((const LPWSTR)L"kernel32.dll");
    if (!base) {
        return 1;
    }

    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
    if (!load_lib) {
        return 2;
    }

    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
    if (!get_proc) {
        return 3;
    }

    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
    = (FARPROC(WINAPI*) (HMODULE, LPCSTR)) get_proc;

    LPVOID u32_dll = _LoadLibraryA("user32.dll");

    int (WINAPI * _MessageBoxW)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) = (int (WINAPI*)(
        _In_opt_ HWND,
        _In_opt_ LPCWSTR,
        _In_opt_ LPCWSTR,
        _In_ UINT)) _GetProcAddress((HMODULE)u32_dll, "MessageBoxW");

    if (_MessageBoxW == NULL) return 4;

    _MessageBoxW(0, L"Hello World!", L"Demo!", MB_OK);

    return 0;
}
```

#### 注意跳转表

如果我们在代码中使用switch条件，它们可能会被编译为跳转表。这是编译器执行的自动优化。在正常的可执行文件中，这是一个有益的解决方案。但当我们编写Shellcode时，我们必须小心，因为它破坏了代码的位置独立性：跳转表是一个需要重定位的结构。

跳转表在汇编中的示例：

```asm
$LN14@switch_sta:
    DD $LN8@switch_sta
    DD $LN6@switch_sta
    DD $LN10@switch_sta
    DD $LN4@switch_sta
    DD $LN2@switch_sta
$LN13@switch_sta:
    DB 0
    DB 1
    DB 4
    DB 4
    DB 4
    DB 4
    DB 4
    DB 4
    DB 4
    DB 4
    DB 4
    DB 4
    DB 4
    DB 2
    DB 4
    DB 4
    DB 4
    DB 4
    DB 3
```

是否生成跳转表的决定由编译器做出。对于少量情况（少于4个），通常不会生成。但如果我们想检查更多条件，我们必须重构代码以避免长switch语句：要么将检查分解为多个函数，要么用if-else语句替换它们。

示例：

```c
// 这个长switch语句将导致生成跳转表：
bool switch_state(char *buf, char *resp) {
    switch (resp[0]) {
        case 0:
            if (buf[0] != '9') break;
            resp[0] = 'Y';
            return true;
        case 'Y':
            if (buf[0] != '3') break;
            resp[0] = 'E';
            return true;
        case 'E':
            if (buf[0] != '5') break;
            resp[0] = 'S';
            return true;
        case 'S':
            if (buf[0] != '8') break;
            resp[0] = 'D';
            return true;
        case 'D':
            if (buf[0] != '4') break;
            resp[0] = 'O';
            return true;
        case 'O':
            if (buf[0] != '7') break;
            resp[0] = 'N';
            return true;
        case 'N':
            if (buf[0] != '1') break;
            resp[0] = 'E';
            return true;
    }
    return false;
}

// 然而，如果我们将其分解为几个部分，我们可以避免生成跳转表：
bool switch_state(char *buf, char *resp) {
    switch (resp[0]) {
        case 0:
            if (buf[0] != '9') break;
            resp[0] = 'Y';
            return true;
        case 'Y':
            if (buf[0] != '3') break;
            resp[0] = 'E';
            return true;
        case 'E':
            if (buf[0] != '5') break;
            resp[0] = 'S';
            return true;
    }
    {
        switch (resp[0]) {
            case 'S':
                if (buf[0] != '8') break;
                resp[0] = 'D';
                return true;
            case 'D':
                if (buf[0] != '4') break;
                resp[0] = 'O';
                return true;
            case 'O':
                if (buf[0] != '7') break;
                resp[0] = 'N';
                return true;
        }
    }
    {
        switch (resp[0]) {
            case 'N':
                if (buf[0] != '1') break;
                resp[0] = 'E';
                return true;
        }
    }
    return false;
}

// 或者，我们可以直接使用if-else重写它：
bool switch_state(char *buf, char *resp) {
    if (resp[0] == 0 && buf[0] == '9') {
        resp[0] = 'Y';
    } else if (resp[0] == 'Y' && buf[0] == '3') {
        resp[0] = 'E';
    } else if (resp[0] == 'E' && buf[0] == '5') {
        resp[0] = 'S';
    } else if (resp[0] == 'S' && buf[0] == '8') {
        resp[0] = 'D';
    } else if (resp[0] == 'D' && buf[0] == '4') {
        resp[0] = 'O';
    } else if (resp[0] == 'O' && buf[0] == '7') {
        resp[0] = 'N';
    } else if (resp[0] == 'N' && buf[0] == '1') {
        resp[0] = 'E';
    }
    return false;
}
```

#### 删除隐式依赖项

我们还必须小心不要在我们的项目中引入一些隐式依赖项。例如，如果我们以以下方式初始化变量：

```c
struct sockaddr_in sock_config = { 0 };
```

这将导致对外部库中的memset的隐式调用。在汇编中，我们将看到带有EXTRN关键字的前置依赖项：

```asm
EXTRN _memset:PROC
```

为了删除此类依赖项，我们需要以不同的方式初始化结构。要么使用我们自己的函数，要么使用保证内联的函数，例如SecureZeroMemory（在此处提到）：

```c
struct sockaddr_in sock_config;
SecureZeroMemory(&sock_config, sizeof(sock_config));
```

#### 准备字符串（可选）

此时，我们还可以将所有使用的字符串重构为基于栈的字符串，如Nick Harbour在以下文章中所述。示例：

```c
char load_lib_name[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
```

编译为汇编后，字符串将如下所示：

```asm
; line 10
mov BYTE PTR_load_lib_name$[ebp], 76 ; 0000004cH
mov BYTE PTR_load_lib_name$[ebp+1], 111 ; 0000006fH
mov BYTE PTR_load_lib_name$[ebp+2], 97 ; 00000061H
mov BYTE PTR_load_lib_name$[ebp+3], 100 ; 00000064H
mov BYTE PTR_load_lib_name$[ebp+4], 76 ; 0000004cH
mov BYTE PTR_load_lib_name$[ebp+5], 105 ; 00000069H
mov BYTE PTR_load_lib_name$[ebp+6], 98 ; 00000062H
mov BYTE PTR_load_lib_name$[ebp+7], 114 ; 00000072H
mov BYTE PTR_load_lib_name$[ebp+8], 97 ; 00000061H
mov BYTE PTR_load_lib_name$[ebp+9], 114 ; 00000072H
mov BYTE PTR_load_lib_name$[ebp+10], 121 ; 00000079H
mov BYTE PTR_load_lib_name$[ebp+11], 65 ; 00000041H
mov BYTE PTR_load_lib_name$[ebp+12], 0

; line 11
lea eax, DWORD PTR_load_lib_name$[ebp]
```

此步骤是稍后在汇编中内联字符串的替代方法。我们可以选择任何我们认为更方便的方法。如果我们选择使用基于栈的字符串，这是重构后我们的代码的样子：

```c
#include <Windows.h>
#include "peb_lookup.h"

int main() {
    wchar_t kernel32_dll_name[] = {'k','e','r','n','e','l','3','2','.','d','l','l', 0};
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);

    if (!base) {
        return 1;
    }

    char load_lib_name[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib) {
        return 2;
    }

    char get_proc_name[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }

    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
    = (FARPROC(WINAPI*) (HMODULE, LPCSTR)) get_proc;

    char user32_dll_name[] = {'u','s','e','r','3','2','.','d','l','l', 0};
    LPVOID u32_dll = _LoadLibraryA(user32_dll_name);

    char message_box_name[] = {'M','e','s','s','a','g','e','B','o','x','W', 0};
    int (WINAPI * _MessageBoxA)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) = (int (WINAPI*)(
        _In_opt_ HWND,
        _In_opt_ LPCWSTR,
        _In_opt_ LPCWSTR,
        _In_ UINT)) _GetProcAddress((HMODULE)u32_dll, message_box_name);

    if (_MessageBoxA == NULL) return 4;

    wchar_t msg_content[] = {'H','e','l','l','o',' ','W','o','r','l','d','!', 0};
    wchar_t msg_title[] = {'D','e','m','o','!', 0};
    _MessageBoxA(0, msg_title, msg_content, MB_OK);

    return 0;
}
```

使用基于栈的字符串有其优缺点。优点是我们可以从C代码中实现它，而不必稍后在汇编中修改它们。然而，在汇编中内联字符串可以自动化（例如通过这个小工具），因此这不是一个大问题（而且它也使混淆字符串更容易）。

在本文中，我决定展示第二种方式：因此，我们不在C文件中更改字符串，而是后处理汇编代码。然而，使用基于栈的字符串的方法作为参考提供。（当然，我们也可以混合使用这两种方法：将一些字符串重构为基于栈的，并内联其余的字符串）。

#### 编译为汇编

现在我们已经准备好将此项目编译为汇编代码。此步骤对于32位和64位版本是相同的——唯一的区别是我们需要选择不同的Visual Studio Native Tools Command Prompt（分别为x86或x64）：

```bash
cl /c /FA /GS- demo.cpp
```

_请记住将`peb_lookup.h`头文件存储在`demo.cpp`所在的目录中——它将自动包含。_

标志`/FA`非常重要，因为它负责生成我们将进一步处理的汇编列表。

##### 禁用Cookie检查

标志`/GS-`负责禁用栈Cookie检查。如果我们忘记使用它，我们的代码将包含以下外部依赖项：

```asm
EXTRN __G5HandlerCheck:PROC
EXTRN __security_check_cookie:PROC
EXTRN __security_cookie:QWORD
```

以及对它们的引用，例如：

```asm
sub rsp, 664 ; _00000298H
mov rax, QWORD PTR __security_cookie
xor rax, rsp

...

mov rcx, QWORD PTR __$ArrayPad${rsp}
xor rcx, rsp
call __security_check_cookie
add rsp, 664 ; _00000298H
pop rdi
pop rsi
ret 0
```

我们仍然可以手动删除它们，如下所示——但建议在编译阶段禁用它们。

将安全Cookie更改为0：

```asm
sub rsp, 664 ; _00000298H
mov rax, 0; QWORD PTR __security_cookie
xor rax, rsp
```

并删除检查安全Cookie的行：

```asm
mov rcx, QWORD PTR __$ArrayPad${rsp}
xor rcx, rsp ;call __security_check_cookie
add rsp, 664 ; _00000298H
pop rdi
pop rsi
ret 0
```

---

### 重构汇编代码

所描述的方法可用于创建32位和64位Shellcode。然而，两者之间存在一些细微差别，步骤可能有所不同。因此，它们将分别描述。

这里描述的大多数步骤都可以使用`masm_shc`工具自动化。然而，我建议至少手动完成整个过程一次，以便更好地理解。

_32位_

首先，我们需要有一个32位汇编代码，通过从32位版本的Visual Studio Native Tools Command Prompt运行`cl /c /FA /GS- demo.cpp`命令生成。

0. 清理汇编代码

首先，我们按原样使用它，并测试是否可以获取输出EXE。我们将尝试使用32位MASM编译汇编代码：

```bash
ml <file_name>.asm
```

由于我们使用FS寄存器，汇编器将打印错误：

```bash
Error A2108: use of register assumed to ERROR
```

为了消除此错误，我们需要在文件顶部（汇编头之后）添加以下行：

```asm
assume fs:nothing
```

进行此修改后，文件应无问题地编译。

运行输出并确保一切正常。此时，我们应该获得一个有效的EXE。然而，如果我们将其加载到PE查看器（例如PE-bear）中，我们将看到尽管我们在C代码中删除了所有依赖项，但结果输出中仍然存在一些依赖项。它仍然有一个导入表。这是因为默认情况下链接了一些标准库。我们需要摆脱它们。

1. 删除其余的外部依赖项

在此步骤中，我们需要摆脱剩余的导入，这些导入来自自动包含的静态库。

注释掉以下包含：

```asm
INCLUDELIB LIBCMT
INCLUDELIB OLDNAMES
```

您还可以注释掉包含列表的行：

```asm
include listing.inc
```

在上一步中，对象文件与包含默认入口点`_mainCRTStartup`的静态库LibCMT链接。现在我们删除了此依赖项。因此，链接器将找不到我们的入口点。我们需要明确指定入口点来链接它：

```bash
ml /c <file_name>.asm
link <file_name>.obj /entry:main
```

或者，一行完成（在编译后立即部署默认链接器）：

```bash
ml /c <file_name>.asm /link /entry:main
```

检查一切是否正常。在PE-bear中打开生成的PE。您将看到现在PE根本没有导入表。此外，代码要小得多。入口点直接从我们的main函数开始。

2. 使代码位置无关：处理字符串

_请注意，如果所有字符串都已重构为基于栈的字符串，则可以省略此步骤，如本文所述。_

为了使Shellcode位置无关，我们不能有任何数据存储在单独的节中。我们只能使用`.text`节来存储所有内容。到目前为止，我们的字符串存储在`.data`节中。因此，我们需要重构汇编代码以将它们内联。

内联字符串的示例：

- 我们从数据段复制字符串，并将其粘贴到将其推入堆栈的行之前。我们通过在字符串之后进行调用来将其推入堆栈：

```asm
call after_kernel32_str
DB 'k', 0, 'e', 0, 'r', 0, 'n', 0, 'e', 0, 'l', 0
DB '3', 0, '2', 0, '.', 0, 'd', 0, 'l', 0, 'l', 0, 0
DB 0
ORG $+2
after_kernel32_str:
;push OFFSET $5689718
```

如果我们的项目有许多字符串，手动内联所有字符串可能会很繁琐，因此可以使用`masm_shc`自动完成。

内联所有字符串后，我们应再次编译应用程序：

```bash
ml /c <file_name>.asm /link /entry:main
```

有时内联字符串会使指令之间的距离过大，并阻止短跳转。我们可以通过将短跳转更改为长跳转轻松修复它。示例：

- 之前：

```asm
jmp SHORT $LN1@main
```

- 之后：

```asm
jmp $LN1@main
```

或者，我们可以复制跳转所指向的指令。

示例——与其跳转到函数末尾以终止分支，我们可以创建一个替代的结束：

```asm
; 替代结束
```

测试生成的可执行文件。如果它不运行，意味着您在内联字符串时犯了错误。

请记住，现在所有字符串都在`.text`节中。因此，如果您正在处理（例如编辑、解码）内联的字符串，首先必须将`.text`节设置为可写（通过更改节头中的标志），否则EXE将崩溃。一旦从EXE中提取Shellcode，它将被加载到RWX（可读、可写、可执行）内存中——因此从Shellcode的角度来看，这没有区别。更多内容将在进一步的示例中描述。

3. 提取和测试Shellcode。
- 在PE-bear中打开应用程序的最终版本。请注意，现在exe应该没有导入表，也没有重定位表。
- 使用PE-bear从文件中转储`.text`节
- 使用`masm_shc`包中的`runshc32.exe`测试Shellcode
- 如果一切顺利，Shellcode应该像EXE一样运行

_64位_

首先，我们需要有一个64位汇编代码，通过从64位版本的Visual Studio Native Tools Command Prompt运行`cl /c /FA /GS- demo.cpp`命令生成。

#### 栈对齐存根

在64位代码的情况下，我们可能还需要确保16字节栈对齐。如果我们要在代码中使用XMM指令，则需要此对齐。如果我们未能按预期对齐堆栈，我们的应用程序将在尝试使用XMM寄存器时崩溃。更多详细信息在@mattifestation的文章中描述，在“确保64位Shellcode中的正确栈对齐”段落下。

@mattifestation提出的确保此对齐的代码：

```asm
_TEXT SEGMENT

; AlignRSP是一个简单的调用存根，确保在调用有效负载的入口点之前堆栈是16字节对齐的。
; 这是必要的，因为Windows中的64位函数假定它们是以16字节栈对齐调用的。当amd64
; Shellcode执行时，您不能保证您的堆栈是16字节对齐的。例如，
; 如果您的Shellcode以8字节栈对齐着陆，任何对Win32函数的调用都可能在调用任何使用XMM寄存器的ASM指令时崩溃（需要16字节对齐）。

AlignRSP PROC
 push rsi ; 保存RSI，因为我们将覆盖它
 mov rsi, rsp ; 保存RSP的值以便恢复
 and rsp, OFFFFFFFFFFFFFFFh ; 将RSP对齐到16字节
 sub rsp, 020h ; 为ExecutePayload分配空间
 call main ; 调用有效负载的入口点
 mov rsp, rsi ; 恢复RSP的原始值
 pop rsi ; 恢复RSI
 ret ; 返回调用者
AlignRSP ENDP

_TEXT ENDS
```

此代码是一个存根，我们应从其中运行我们的main函数，以便在执行任何代码之前对齐堆栈。

我们应将其附加到文件的第一`_TEXT SEGMENT`之前。一旦我们添加此存根，它应成为我们应用程序的新入口点：

```bash
ml64 <file.asm> /link /entry:AlignRSP
```

0. 清理汇编代码

首先，我们按原样使用它，并测试是否可以获取有效输出。我们将尝试使用64位MASM（从64位版本的Visual Studio Native Tools Command Prompt）编译汇编代码：

```bash
ml64 <file_name>.asm
```

这次我们得到几个错误。这是由于生成的列表与MASM不完全兼容，我们需要手动修复所有兼容性问题。我们将得到类似的错误列表：

```bash
shellcode_task_step1.asm(75) : error A2006:undefined symbol : FLAT
shellcode_task_step1.asm(86) : error A2006:undefined symbol : FLAT
shellcode_task_step1.asm(98) : error A2006:undefined symbol : FLAT
shellcode_task_step1.asm(116) : error A2006:undefined symbol : FLAT
shellcode_task_step1.asm(120) : error A2006:undefined symbol : FLAT
shellcode_task_step1.asm(132) : error A2006:undefined symbol : FLAT
shellcode_task_step1.asm(133) : error A2006:undefined symbol : FLAT
shellcode_task_step1.asm(375) : error A2027:operand must be a memory expression
shellcode_task_step1.asm(30) : error A2006:undefined symbol : $LN16
shellcode_task_step1.asm(31) : error A2006:undefined symbol : $LN16
shellcode_task_step1.asm(36) : error A2006:undefined symbol : $LN13
shellcode_task_step1.asm(37) : error A2006:undefined symbol : $LN13
shellcode_task_step1.asm(41) : error A2006:undefined symbol : $LN7
shellcode_task_step1.asm(42) : error A2006:undefined symbol : $LN7
```

- 我们需要手动从asm文件中删除单词FLAT。只需将`FLAT::`替换为空。
- 我们需要删除pdata和xdata段
- 我们需要将gs寄存器的引用修复为`gs:[96]`

从：

```asm
mov rax, QWORD PTR gs:96
```

到：

```asm
mov rax, QWORD PTR gs:[96]
```

现在文件应正确汇编。运行生成的可执行文件并在PE-bear中检查它。

1. 删除其余的外部依赖项

在此步骤中，我们需要摆脱剩余的导入，这些导入来自自动包含的静态库。

就像在32位版本中一样，我们需要注释掉自动添加的包含：

```asm
INCLUDELIB LIBCMT
INCLUDELIB OLDNAMES
```

如果某些函数已从这些库中自动添加，我们需要像在32位版本的类似部分中所述那样摆脱它们。

编译文件，明确指定入口点：

```bash
ml64 /c <file_name>.asm /link /entry:<entry_function>
```

2. 使代码位置无关：处理字符串

_请注意，如果所有字符串都已重构为基于栈的字符串，则可以省略此步骤，如本文所述。_

类似于32位版本，我们需要删除所有对`.text`节以外的引用。在这种情况下，这意味着内联所有字符串。这将类似于32位版本，但这次函数的参数通过寄存器提供，而不是推入堆栈。因此，您需要将其偏移量弹出到适当的寄存器中。

64位版本的内联字符串示例：

```asm
call after_msgbox_str
    DB "MessageBoxW", 0
after_msgbox_str:
    pop rdx
    lea rdx, OFFSET $5090389
    mov rcx, QWORD PTR u32_dll$[rsp]
    call QWORD PTR _GetProcAddress$[rsp]
```

3. 提取和测试Shellcode - 类似于32位版本：
- 在PE-bear中打开应用程序的最终版本。请注意，现在exe应该没有导入表，也没有重定位表。
- 使用PE-bear从文件中转储`.text`节
- 使用`masm_shc`包中的`runshc64.exe`测试Shellcode
- 如果一切顺利，Shellcode应该像EXE一样运行

---

### 扩展示例 - 演示服务器

到目前为止，我们准备了一个小演示示例，显示一个消息框。但是，如果是一些更功能性的东西呢？它也能工作吗？

在本章中，我们将查看另一个示例——一个小的本地服务器。它是White Rabbit crackme的一部分代码。此部分在3个连续端口上打开套接字——一个接一个——我们应该敲击这些端口。

这是我们可以编译为汇编的C代码`knock.cpp`：

```c
#include <Windows.h>
#include "peb_lookup.h"

#define LOCALHOST_ROT13 ">?D;=;=;>"

typedef struct {
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName);
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
} t_mini_iat;

typedef struct {
    int (PASCAL FAR * _MSAStartup)(
        _In_ WORD wVersionRequired,
        _Out_ LPMSADATA lpMSAData);

    SOCKET(PASCAL FAR * _socket)(
        _In_ int af,
        _In_ int type,
        _In_ int protocol);

    unsigned long (PASCAL FAR * _inet_addr)(_In_z_ const char FAR * cp);

    int (PASCAL FAR * _bind)(
        _In_ SOCKET s,
        _In_reads_bytes_(namelen) const struct sockaddr FAR *addr,
        _In_ int namelen);

    int (PASCAL FAR * _listen)(
        _In_ SOCKET s,
        _In_ int backlog);

    SOCKET(PASCAL FAR * _accept)(
        _In_ SOCKET s,
        _Out_writes_bytes_opt(*addrlen) struct sockaddr FAR *addr,
        _Inout_opt_int FAR *addrlen);

    int (PASCAL FAR * _recv)(
        _In_ SOCKET s,
        _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
        _In_ int len,
        _In_ int flags);

    int (PASCAL FAR * _send)(
        _In_ SOCKET s,
        _In_reads_bytes_(len) const char FAR * buf,
        _In_ int len,
        _In_ int flags);

    int (PASCAL FAR * _Closesocket)(IN SOCKET s);
    u_short(PASCAL FAR * _htons)(_In_ u_short hostshort);

    int (PASCAL FAR * _MSACleanup)(void);

} t_socket_iat;

bool init_iat(t_mini_iat &iat) {
    LPVOID base = get_module_by_name((const LPWSTR)L"kernel32.dll");
    if (!base) {
        return false;
    }

    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
    if (!load_lib) {
        return false;
    }

    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
    if (!get_proc) {
        return false;
    }

    iat._LoadLibraryA = (HMODULE(WINAPI*)(LPCSTR)) load_lib;
    iat._GetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;
    return true;
}

bool init_socket_iat(t_mini_iat &iat, t_socket_iat &sIAT) {
    LPVOID WS232_dll = iat._LoadLibraryA("WS2_32.dll");

    sIAT._MSAStartup = (int (PASCAL FAR *)(
        _In_ WORD,
        _Out_ LPMSADATA)) iat._GetProcAddress((HMODULE)WS232_dll, "MSAStartup");

    sIAT._socket = (SOCKET(PASCAL FAR *)(
        _In_ int af,
        _In_ int type,
        _In_ int protocol)) iat._GetProcAddress((HMODULE)WS232_dll, "socket");

    sIAT._inet_addr = (unsigned long (PASCAL FAR *)(
        _In_z_ const char FAR * cp)) iat._GetProcAddress((HMODULE)WS232_dll, "inet_addr");

    sIAT._bind = (int (PASCAL FAR *)(
        _In_ SOCKET s,
        _In_reads_bytes_(namelen) const struct sockaddr FAR *addr,
        _In_ int namelen)) iat._GetProcAddress((HMODULE)WS232_dll, "bind");

    sIAT._listen = (int (PASCAL FAR *)(
        _In_ SOCKET s,
        _In_ int backlog)) iat._GetProcAddress((HMODULE)WS232_dll, "listen");

    sIAT._accept = (SOCKET(PASCAL FAR *)(
        _In_ SOCKET s,
        _Out_writes_bytes_opt(*addrlen) struct sockaddr FAR *addr,
        _Inout_opt_int FAR *addrlen)) iat._GetProcAddress((HMODULE)WS232_dll, "accept");

    sIAT._recv = (int (PASCAL FAR *)(
        _In_ SOCKET s,
        _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
        _In_ int len,
        _In_ int flags)) iat._GetProcAddress((HMODULE)WS232_dll, "recv");

    sIAT._send = (int (PASCAL FAR *)(
        _In_ SOCKET s,
        _In_reads_bytes_(len) const char FAR * buf,
        _In_ int len,
        _In_ int flags)) iat._GetProcAddress((HMODULE)WS232_dll, "send");

    sIAT._Closesocket = (int (PASCAL FAR *)(
        IN SOCKET s)) iat._GetProcAddress((HMODULE)WS232_dll, "closesocket");

    sIAT._htons = (u_short(PASCAL FAR *)(
        _In_ u_short hostshort)) iat._GetProcAddress((HMODULE)WS232_dll, "htons");

    sIAT._MSACleanup = (int (PASCAL FAR *)(
        void)) iat._GetProcAddress((HMODULE)WS232_dll, "WSACleanup");

    return true;
}

bool switch_state(char *buf, char *resp) {
    switch (resp[0]) {
        case 0:
            if (buf[0] != '9') break;
            resp[0] = 'Y';
            return true;
        case 'Y':
            if (buf[0] != '3') break;
            resp[0] = 'E';
            return true;
        case 'E':
            if (buf[0] != '5') break;
            resp[0] = 'S';
            return true;
        default:
            resp[0] = 0; break;
    }
    return false;
}

inline char* rot13(char *str, size_t str_size, bool decode) {
    for (size_t i = 0; i < str_size; i++) {
        if (decode) {
            str[i] -= 13;
        } else {
            str[i] += 13;
        }
    }
    return str;
}

bool listen_for_connect(t_mini_iat &iat, int port, char resp[4]) {
    t_socket_iat sIAT;
    if (!init_socket_iat(iat, sIAT)) {
        return false;
    }
    const size_t buf_size = 4;
    char buf[buf_size];

    LPVOID u32_dll = iat._LoadLibraryA("user32.dll");

    int (WINAPI * _MessageBoxW)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) = (int (WINAPI*)(
        _In_opt_ HWND,
        _In_opt_ LPCWSTR,
        _In_opt_ LPCWSTR,
        _In_ UINT)) iat._GetProcAddress((HMODULE)u32_dll, "MessageBoxW");

    bool got_resp = false;
    WSADATA wsaData;
    SecureZeroMemory(&wsaData, sizeof(wsaData));
    /// code:
    if (sIAT._MSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    struct sockaddr_in sock_config;
    SecureZeroMemory(&sock_config, sizeof(sock_config));
    SOCKET listen_socket = 0;
    if ((listen_socket = sIAT._socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        _MessageBoxW(NULL, L"Creating the socket failed", L"Stage 2", MB_ICONEXCLAMATION);
        sIAT._MSACleanup();
        return false;
    }

    char *host_str = rot13(LOCALHOST_ROT13, _countof(LOCALHOST_ROT13) - 1, true);
    sock_config.sin_addr.s_addr = sIAT._inet_addr(host_str);
    sock_config.sin_family = AF_INET;
    sock_config.sin_port = sIAT._htons(port);

    rot13(host_str, _countof(LOCALHOST_ROT13) - 1, false); // 重新编码

    bool is_ok = true;
    if (sIAT._bind(listen_socket, (SOCKADDR*)&sock_config, sizeof(sock_config)) == SOCKET_ERROR) {
        is_ok = false;
        _MessageBoxW(NULL, L"Binding the socket failed", L"Stage 2", MB_ICONEXCLAMATION);
    }
    if (sIAT._listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        is_ok = false;
        _MessageBoxW(NULL, L"Listening the socket failed", L"Stage 2", MB_ICONEXCLAMATION);
    }

    SOCKET conn_sock = SOCKET_ERROR;
    while (is_ok && (conn_sock = sIAT._accept(listen_socket, 0, 0)) != SOCKET_ERROR) {
        if (sIAT._recv(conn_sock, buf, buf_size, 0) > 0) {
            got_resp = true;
            if (switch_state(buf, resp)) {
                sIAT._send(conn_sock, resp, buf_size, 0);
                sIAT._Closesocket(conn_sock);
                break;
            }
        }
        sIAT._Closesocket(conn_sock);
    }

    sIAT._Closesocket(listen_socket);
    sIAT._MSACleanup();
    return got_resp;
}

int main() {
    t_mini_iat iat;
    if (!init_iat(iat)) {
        return 1;
    }
    char resp[4];
    SecureZeroMemory(resp, sizeof(resp));
    listen_for_connect(iat, 1337, resp);
    listen_for_connect(iat, 1338, resp);
    listen_for_connect(iat, 1339, resp);
    return 0;
}
```

在这个示例中，我引入了一些结构，它们将作为我们Shellcode的伪IAT。以这种方式封装加载的函数非常方便——我们还可以在各种项目中重用这些代码片段，以避免重写负责加载函数的部分代码。

我们还可以看到，一个字符串使用ROT13编码，并在使用前解码。在我们内联此字符串后，我们必须将`.text`节设置为可写——因为字符串将被修改。在使用字符串后，我们必须重新编码它，以保持其初始状态以供进一步使用。

请注意，我没有使用`strlen`函数——而是使用了一个宏`_countof`来计算元素的数量。由于`strlen`给出的长度不包括终止符`\0`，其等效项将是：`_countof(str) - 1`：

```c
rot13(LOCALHOST_ROT13, _countof(LOCALHOST_ROT13) - 1, true);
```

#### 构建

可以通过以下命令构建项目：

```bash
cl /c /FA /GS- main.cpp
masm_shc.exe main.asm main1.asm
ml main1.asm /link /entry:main
```

#### 运行

使用PE-bear转储`.text`节。保存为：`serv32.bin`或`serv64.bin`，视情况而定。

根据构建的位数，使用`runshc32.exe`或`runshc64.exe`（可在此处获取）运行它。

示例：

```bash
runshc32.exe serv32.bin
```

#### 测试

在Process Explorer中检查适当的端口是否打开。

为了测试，我们可以使用以下Python（Python2.7）脚本`knock_test.py`：

```python
import socket
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Send to the Crackme")
    parser.add_argument('--port', dest="port", default="1337", help="Port to connect")
    parser.add_argument('--buf', dest="buf", default="@@", help="Buffer to send")
    args = parser.parse_args()
    my_port = int(args.port, 10)
    print '[+] Connecting to port: ' + hex(my_port)
    key = args.buf
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', my_port))
        s.send(key)
        result = s.recv(512)
        if result is not None:
            print "[+] Response: " + result
        s.close()
    except socket.error:
        print "Could not connect to the socket. Is the crackme running?"

if __name__ == "__main__":
    sys.exit(main())
```

我们将发送预期的数字，导致内部状态发生变化。有效的请求/响应：

```bash
C:\Users\tester\Desktop>C:\Python27\python.exe ping.py --buf 9 --port 1337
[+] Connecting to port: 0x539
[+] Response: Y

C:\Users\tester\Desktop>C:\Python27\python.exe ping.py --buf 3 --port 1338
[+] Connecting to port: 0x53a
[+] Response: E

C:\Users\tester\Desktop>C:\Python27\python.exe ping.py --buf 5 --port 1339
[+] Connecting to port: 0x53b
[+] Response: S
```

在最后一个响应后，Shellcode应终止。

在有效端口上发送无效请求的情况下，响应将为空，例如：

```bash
C:\Users\tester\Desktop>C:\Python27\python.exe ping.py --buf 9 --port 1338
[+] Connecting to port: 0x53a
[+] Response:
```

---

### 结论

由于我们将C代码编译为有效的汇编代码，我们可以自由地进一步处理它。这是有趣的部分开始的地方。

与高级语言相比，汇编代码的自动处理相当简单。如果我们想部署一些自动混淆，它提供了许多优势。通过逐行处理汇编文件，我们可以植入一些自动生成的垃圾代码或虚假条件。我们可以用它们的等效指令替换一些指令，实现简单的多态性。我们还可以在我们的代码块之间散布反调试技术。有许多可能性——然而，混淆的主题非常广泛，超出了本文的范围。

我的目标是展示创建汇编中的Shellcode并不需要太多工作。我们真的不必花费数小时逐行编写代码。利用MSVC提供的可能性就足够了。尽管C编译器生成的代码需要一些后处理，但实际上它很简单，并且可以在很大程度上自动化。

---

**-smelly__vx, 2022年12月4日**