
[简体中文](README-zh.md)|[English](README.md)

## 简介

WBBlades是基于`Mach-O`文件解析的工具集，包括无用代码检测（支持`OC`和`Swift`）、包大小分析（支持单个静态库/动态库的包大小分析）、点对点崩溃解析（基于系统日志，支持有符号状态和无符号状态）、基于Mach-O的Class自动提取并Hook能力。主要利用了__Text汇编代码分析、架构提取、符号表剥离、DYSM文件提取、崩溃文件(ips)解析、等技术手段实现，支持big method /small method 解析 以及 iOS 15以上关于  dyld_chained_fixups的处理。

3.0版本在原来基于命令行运行上述工具的基础上，对工具集进行了全面的可视化实现，开箱即用，专为研发提效而设计。另外，在疑难崩溃解析上，针对一些不易复现、且通用工具无法收集的崩溃（被操作系统直接杀死App进程场景），提供了基于系统日志的点对点崩溃解析功能。

## 安装

```
$ git clone https://github.com/wuba/WBBlades.git
$ cd WBBlades
$ pod install
```
## 使用
### 可视化工具用法
target选择：WBBladesCrashApp

点击左侧功能区按钮，点击进入无用类检测、包大小检测等工具，根据工具内的提示进行操作即可，具体的数据会输出到文本框中；
> 可视化工具详细介绍: [可视化工具详细介绍](UsageDetail.md)

### 命令行工具blades用法
target选择：WBBlades，编译运行，生成命令行工具
将生成的产物blades 拷贝至 /usr/local/bin 下，具体操作如：
sudo cp ${Your_BUILD_DIR}/blades /usr/local/bin

- 无用代码检测 `OC` & `Swift`

   `$ blades -unused xxx.app -from xxx.a xxx.a ....`

  > -from 标识只分析以下静态库中的无用代码，不加此参数默认为APP中全部类

- 包大小分析 (直接测算.a |.framework链接后的大小)

  `$ blades -size xxx.a xxx.framework ....`

  > 支持输入一个文件夹路径，输入后该文件下所有的静态库都会被分析

- 无符号表日志符号化（在丢失符号表的情况下，尝试`OC`崩溃堆栈符号化，不支持`Swift`）

  `$ blades -symbol xxx.app -logPath xxx.ips`
  
  

## 工具特性介绍

### 无用代码（无用类）检测支持范围

| 说明                     | 是否支持 | 代码示例                                     |
| :----------------------- | :------: | :------------------------------------------- |
| OC 的类的静态调用        |    ✅     | `[MyClass new]`                              |
| OC 的动态调用            |    ✅     | `NSClassFromString(@"MyClass")`              |
| OC 字符串拼接动态调用    |    ❌     | `NSClassFromString(@"My" + @"Class")`        |
| OC load方法使用          |    ✅     | `+load{...} `                                |
| OC & Swift 被继承        |    ✅     | `SomClass : MyClass`                         |
| OC & Swift 作为属性      |    ✅     | `@property (strong,atomic) MyClass *obj;`    |
| Swift 类直接调用         |    ✅     | `MyClass.init()`                             |
| Swift 通过runtime调用    |    ❌     | `objc_getClass("Demo.MyClass")`              |
| Swift 泛型参数           |    ✅     | `SomeClass<MyClass>.init()`                  |
| Swfit 类在OC中动态调用   |    ✅     | `NSClassFromString("Demo.MyClass")`          |
| Swift 容器中作为类型声明 |    ❌     | `var array:[MyClass]`                        |
| Swift 多重嵌套           |    ✅     | ` class SomeClass {class MyClass {...} ...}` |

### 包大小分析工具

支持快速检测一个静态库的链接后大小。无需编译链接。**举例说明：如果你想知道一个接入或更新一个SDK对会增加多少包大小，可以用`blades -size `来预估下大小**，而无需将SDK接入编译链接成功后进行测算。



### 无符号表日志符号化工具

在丢失dSYM文件的情况下，尝试通过`blades -symbol`恢复日志。**例如某次打包，在一段时间后符号表被清除，但是保留了app文件，这种情况下可以考虑使用blades进行符号化**。在工具使用前应先注意几点：

- 如果你的app是debug包或者没有剥离符号表的包，那么可以通过`dsymutil app -o xx.dSYM `来提取符号表。然后用符号表进行日志符号化。
- 工具只适用于OC的场景，其原理为通过分析Mach-O中OC方法地址来确定崩溃的函数。因此不适用于Swfit、C、C++场景。另外，工具并非万能，仅作为应急补充技术手段，日常情况下还是推荐用符号表进行日志符号化。


## 如何贡献&反馈问题

我们诚挚地希望开发者提出宝贵的意见和建议，开发者可以通过提交PR或者Issue来反馈建议和问题。

## 相关技术文章

- [58 同城 iOS 客户端组件体积分析与统计实践](https://blog.csdn.net/csdnnews/article/details/100354658/)
- [基于mach-o+反汇编的无用类检测](https://www.jianshu.com/p/c41ad330e81c)
- [开源｜WBBlades：基于Mach-O文件解析的APP分析工具](https://mp.weixin.qq.com/s/HWJArO5y9G20jb2pqaAQWQ)
- [从Mach-O角度谈谈Swift和OC的存储差异](https://www.jianshu.com/p/ef0ff6ee6bc6)
- [Swift Hook新思路--虚函数表](https://mp.weixin.qq.com/s/mjwOVdPZUlEMgLUNdT6o9g)

## 致谢

GitHub地址：[https://github.com/aquynh/capstone](https://github.com/aquynh/capstone "GitHub for capstone")

GitHub地址：[https://github.com/Sunnyyoung/SYFlatButton](https://github.com/Sunnyyoung/SYFlatButton "GitHub for SYFlatButton")

GitHub地址：[https://github.com/nygard/class-dump](https://github.com/nygard/class-dump "GitHub for class-dump")

GitHub地址：[https://github.com/alexrozanski/PXListView](https://github.com/alexrozanski/PXListView "GitHub for PXListView")

GitHub地址：[https://github.com/steventroughtonsmith/cartool](https://github.com/steventroughtonsmith/cartool "cartool")

DWARF地址：[https://www.prevanders.net/dwarf.html#releases](https://www.prevanders.net/dwarf.html#releases "Source Code for DWARF") 

