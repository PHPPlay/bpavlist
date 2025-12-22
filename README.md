# bpavlist
我的一些免杀笔记与网上一些文章，记录和备份一下防丢

学吧，永远都学不完的，这个基础学完了，然后学pe、汇编、windows、逆向、太多了

## 书籍
《WINDOWS黑客编程技术详解》
《EvadingEDR》
《加密与解密》系列

## 教程
这里推荐maldevacademy

https://maldevacademy.com/maldev-course/syllabus
这里我整理一下


| 月份       | 课程1                          | 课程2                          | 课程3                          |
|------------|-------------------------------|-------------------------------|-------------------------------|
| 2023年4月  | Windows 操作系统基础           | Windows API 与 PE 文件格式详解 | 杀毒软件检测机制               |
|            | Payload 布置 ×3 种方法         | Payload 加密 ×3 种方案         | Payload 混淆 ×4 种技术         |
|            | 自定义工具演示                 | 本地 Payload 执行              | 远程 Payload 执行              |
|            | Payload 分阶段传输             | 利用 NtCreateUserProcess 创建进程 | 恶意软件二进制签名             |
|            | 进程枚举 ×2 种方法             | 线程劫持 ×4 种技术             | 阻止 DLL 加载策略              |
|            | 本地 APC 注入                  | 远程 APC 注入                  | 通过回调函数执行 Payload       |
|            | 间接系统调用                   | 本地内存映射注入               | 远程内存映射注入               |
|            | 本地函数覆盖                   | EDR 基础知识                   | 命令行参数欺骗 ×2 种方法       |
|            | 远程 Payload 执行              | Payload 分阶段传输             | Hell's Gate 技术               |
| 2023年5月  | 利用 EDR 规避检测              | 通过系统调用枚举线程           | 自定义 WinAPI 函数             |
|            | MASM 汇编入门                  |                                |                                |
| 2023年6月  | 硬件断点挂钩技术 ×2            | 硬件断点提取凭据               | 通过文件膨胀绕过检测           |
|            | 自定义协议处理器               | 自定义文件扩展名               | BaseN 编码器 - 熵值降低挑战    |
| 2023年7月  | 事件跟踪（ETW）入门            | 探索 ETW 工具                  | ETW 绕过 - 字节补丁            |
|            | ETW 绕过 - 改进版补丁          | 无补丁 ETW 绕过 - 硬件断点     | ETW 提供程序会话劫持           |
|            | 转发函数挑战                   | 解钩所有 DLL 挑战              | 编写自定义 Shellcode 挑战      |
| 2023年8月  | AMSI 防护机制入门              | AMSI 绕过 - 字节补丁           | 无补丁 AMSI 绕过 - 硬件断点    |
|            | 构建带数字版权管理的恶意软件   | 恶意软件自毁日期挑战           | API 集解析挑战                 |
|            | 反向 Shell Shellcode 编写挑战  |                                |                                |
| 2023年11月 | TLS 回调反调试                 | 利用纤程执行 Payload           | 恶意软件目录部署               |
|            | 编译时哈希混淆挑战             | 编译时字符串加密挑战           | 用户共享数据延迟挑战           |
| 2024年1月  | 无线程注入                     | 模块覆盖                       | 模块重载                       |
|            | 进程镂空                       | 无 WinAPI 生成加密密钥挑战     | SystemFunction040 加密挑战     |
|            | 向 PE 文件插入自定义节挑战     |                                |                                |
| 2024年3月  | 幽灵进程注入                   | Herpaderping 进程注入          | Shellcode 反射型 DLL 注入      |
|            | 幽灵镂空                       | Herpaderply 镂空               | 远程模块覆盖挑战               |
|            | 进程镂空挑战                   | PSExec 实现挑战                |                                |
| 2024年4月  | 无补丁无线程注入 - 硬件断点    | 篡改系统调用 - 硬件断点        | 利用 EDR 规避检测 - 阻止 EDR 行动 |
|            | 利用 EDR 规避检测 - EDR LOLBINs |                                |                                |
| 2024年5月  | 进程催眠                       | 缓冲区溢出（BoF）入门          | 编写 BoF 文件                  |
|            | BoF 执行                       | 反分析 - IP 白名单挑战         | 域名注册自毁开关挑战           |
|            | 恶意软件工作时间限制挑战       |                                |                                |
| 2024年7月  | 利用 EDR 规避检测 - 查找内部排除列表 | 睡眠混淆技术入门               | Foliage 睡眠混淆               |
|            | Ekko 睡眠混淆                  | 通过栈欺骗实现 Ekko            | LSASS 转储 BoF 挑战            |
|            | ChaCha20 加密算法挑战          | 无线程 Shellcode 注入 - BoF 挑战 |                                |
| 2024年8月  | 令牌操纵                       | 库代理加载                     | 基于 Ekko 的堆加密             |
|            | 启用 CFG 的 Ekko 挑战          | 恢复文件节保护的 Ekko 挑战     | 使用 RtlEncryptMemory 的 Ekko 挑战 |
| 2024年11月 | .NET 程序集执行入门            | 通过修补绕过 Microsoft Defender | 修补 System.Environment.Exit   |
|            | 隐写术 Shellcode 加载器挑战    | 模块覆盖对象文件加载器挑战     | Zilean 堆栈复制挑战            |
| 2025年1月  | KnownDll 缓存投毒注入          | 跨架构注入：x86 → x64         | 截屏并保存至内存               |
|            | 通过 APC 写入进程内存挑战      |                                |                                |
| 2025年2月  | 文件时间戳篡改挑战             | 定时器 API 代理执行内存分配     | 工作项 API 代理执行内存分配    |
|            | 工作项 API 代理执行线程创建    |                                |                                |
| 2025年4月  | 主模块源码现提供 C 和 Rust 版本 |                                |                                |
| 2025年5月  | LSASS 转储入门                 | 获取 LSASS 句柄并绕过 PPL      | 通过句柄复制转储 LSASS         |
|            | 通过 RtlReportSilentProcessExit 转储 LSASS | 通过 Seclogon 竞态条件转储 LSASS |                                |
| 2025年7月  | 导出 SAM 数据库                | 远程导出 SAM 数据库            | 从磁盘导出 SAM 数据库          |
|            | 使用 MS-SAMR 枚举域信息        |                                |                                |
| 2025年8月  | 导出火狐浏览器 Cookie          | 导出火狐保存的登录凭证         | 导出谷歌浏览器 Cookie          |
|            | 导出谷歌保存的登录凭证         |                                |                                |





学习方法这个自己去找




## github项目

shellcodeloader加载方式大全 ---------
https://github.com/SaadAhla/Shellcode-Hide
执行shellcode的各种方法 ---------
https://github.com/Wra7h/FlavorTown
傻瓜恶意软件开发 ---------
https://github.com/chvancooten/maldev-for-dummies
shellcode加密混淆 ---------
https://github.com/EgeBalci/sgn

