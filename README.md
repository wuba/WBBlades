

## 简介

WBBlades是基于`Mach-O`文件解析的工具集，包括无用代码检测（支持`OC`和`Swift`）、静态库体积分析、无符号表日志恢复。

## 安装

```
$ git clone https://github.com/wuba/WBBlades.git
$ cd WBBlades
$ make install
```

## 使用

- 无用代码检测 `OC` & `Swift`

   `$ blades -unused xxx.app -from xxx.a xxx.a ....`

  > -from 标识只分析以下静态库中的无用代码，不加此参数默认为APP中全部类

- 静态库体积分析

  `$ blades -size xxx.a xxx.framework ....`

- 无符号表日志恢复

  `$ blades -symbol xxx.app -logPath xxx.ips`

## 一些示例

支持`OC`和`Swift` 的无用代码检测，`OC`仅支持`Class`级别的检测，**Swift目前只支持`Class`结构，不支持`Struct`、`Enum`等**。

| 说明                     | 标记为被使用 | 代码示例                                     |
| :----------------------- | :----------: | :------------------------------------------- |
| OC 的类的静态调用        |      ✅       | `[MyClass new]`                              |
| OC 的动态调用            |      ✅       | `NSClassFromString(@"MyClass")`              |
| OC 字符串拼接动态调用    |      ❌       | `NSClassFromString(@"My" + @"Class")`        |
| OC load方法使用          |      ✅       | `+load{...} `                                |
| OC & Swift 被继承        |      ✅       | `SomClass : MyClass`                         |
| OC & Swift 作为属性      |      ✅       | `@property (strong,atomic) MyClass *obj;`    |
| Swift 类直接调用         |      ✅       | `MyClass.init()`                             |
| Swift 通过runtime调用    |      ❌       | `objc_getClass("Demo.MyClass")`              |
| Swift 泛型参数           |      ✅       | `SomeClass<MyClass>.init()`                  |
| Swfit 类在OC中动态调用   |      ✅       | `NSClassFromString("Demo.MyClass")`          |
| Swift 容器中作为类型声明 |      ❌       | `var array:[MyClass]`                        |
| Swift 多重嵌套           |      ✅       | ` class SomeClass {class MyClass {...} ...}` |

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
