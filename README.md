
## 简介

WBBlades是基于`Mach-O`文件解析的工具集，包括无用代码检测（支持`OC`和`Swift`）、包大小分析、无符号表日志符号化。

## 安装

```
$ git clone https://github.com/wuba/WBBlades.git
$ cd WBBlades
$ make install
```
如果出现类似`[1]    70390 killed     blades`提示，可以尝试重新`make install`

## 使用

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



## Developing for WBBlades

邓竹立

## Contributing for WBBlades

邓竹立，彭飞，朴惠姝，曾庆隆，林雅明

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
