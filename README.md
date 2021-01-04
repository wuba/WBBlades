
# WBBlades：基于Mach-O的包大小分析、无用类检测、崩溃解析工具

一款基于mach-o技术，针对多pods，简单高效地进行<strong>代码体积检测、无用类检测和无符号崩溃日志解析</strong>的工具。

（WBBlades: Based on mach-o technology, a simple and efficient code size detection, unused class detection and unsigned crash log parser for multi-pods.）


## 特性
* 支持快速检测SDK的接入体积，输入路径即可分析出该路径下的静态库体积、资源体积以及总体积，无需编译链接过程；
*    无用类检测支持对类的继承、动态调用、自身类调用、属性及成员变量的识别；
*    在没有符号表的情况下，可以通过二进制文件的解析实现OC代码的日志符号化；
*    易扩展、易推广，具备可在终端上独立运行能力，可通过脚本调用、传参。

## 背景
   随着公司业务不断扩展，APP体积也随之增大，APP包瘦身逐渐成为我们的重要任务；同时，APP崩溃问题也是我们关注的重点。为了解决现存问题，优化APP性能，我们基于Mach-O解析与反汇编技术，产出了WBBlades工具集——静态库体积分析工具，工程无用类检测工具，以及无符号崩溃解析工具。
   
   静态库体积分析工具可以帮助开发者快速评估一个静态库在链接到可执行程序后的体积，相比于同类工具，此工具无需开发者对代码进行编译链接，可以在静态库SDK在接入前获知接入的体积成本。
   
   无用类检测工具是基于Mach-O文件分析产生的数据，通过Mach-O文件分析和反汇编技术的应用，解决RN代码、类的动态调用、类的继承关系、自调用等问题，从一定程度上提高无用类检测的准确性。
   
   无符号日志解析工具可以帮助开发者在缺少符号表的情况下实现日志解析。
   
   
## 优势
* **体积分析 VS linkmap**

主流的体积分析方案是通过linkmap文件分析，本方案与linkmap文件分析相比，使用较为简单，无需编译链接即可分析统计。

准确性：分析结果与linkmap十分接近，偏差在10%以内。

* **无用类检测 VS otool+Mach-O**

与通过otool命令直接采用classlist与classref做差集的方案相比，WBBlades具有以下几点优势

|       场景       | WBBlades |  otool  |
| --------------|--------------|---------|
| 动态调用类  | 支持及识别 | 不支持|
| 基类、属性  | 支持及识别 | 不支持|
| 类内调用     | 支持及识别  | 不支持|

耗时问题：由于WBBlades需要遍历大量指令，因此我们提供了圈选功能，开发者可以查看某几个SDK或某几个Pod的无用类，从而减少耗时。

## 环境安装
   * Mac
   * Xcode

## 使用
<i>注意：使用工具时，物料（如APP、静态库、ips等）的路径不能出现空格或中文。</i>

下载源码，打开并运行WBBlades.xcodeproj。找到Products-WBBlades，将其拖入命令行。

*  <strong>静态库体积分析</strong>

	在拖入的WBBlades文件路径后面加空格，输入-size，空格，拖入需要解析的静态库路径，路径间同样以空格隔开。

	输入参数示例：

	```WBBlades -size xxx.a xxx.framework ....```
	
	按回车进行解析，解析结果会保存在 <i>~/Desktop/WBBladesResult.plist</i> 文件中。
	
* <strong>无用类检测</strong>

	在刚刚拖入的WBBlades文件路径后面加空格，输入-unused，空格，拖入需要解析的app文件路径——最好是Xcode本地打出来的Debug包；如果只需要检测部分静态库，则输入-from，拖入需要解析的静态库路径，可以拖入一个到多个，将只检测这些静态库下的类的使用情况。

	输入参数示例：
	
	```WBBlades -unused xxx.app -from xxx.a xxx.a ....```
	
	(-from 标识只分析以下静态库中的无用类，不加此参数默认为APP中全部类)
	
	按回车进行解析，解析结果会保存在 <i>~/Desktop/WBBladesClass.plist</i> 文件中。
	
* <strong>无符号崩溃解析</strong>

	在刚刚拖入的WBBlades文件路径后面加空格，输入-symbol，空格，拖入需要解析的可执行文件（只能输入一个可执行文件），输入-offsets，输入崩溃日志的偏移地址组成的字符串，偏移地址间以英文“,“间隔，中间没有空格。
	
	输入参数示例： 
	
	```WBBlades -symbol xxx.app -offsets 1234,5678,91011```
	
	按回车进行解析，解析结果会保存在桌面 <i>~/Desktop/WBBladesCrash.plist</i> 文件中。
	
   
## 后期规划

我们将持续优化和改进工具的准确性和易用性：目前体积分析工具对C++/Swift编译的文件存在一定的误差，这是我们后期要重点关注的问题。现阶段工具集只支持arm64架构的Mach-O文件，如果有必要我们将增加对Fat文件及armv7架构的支持。
    
## Developing for WBBlades
邓竹立

## Contributing for WBBlades
邓竹立，彭飞，朴惠姝，曾庆隆，林雅明

## Running samples
1. 运行代码。
2. demo 所需物料在“TestNeed“文件夹下，主要包括：

	（1）WBBladesDemoApp.app ：需要被分析的程序。
	
	（2）crash.ips ：WBBladesDemoApp.app的崩溃日志。

	（3）libStatic.a ：WBBladesDemoApp.app中所接入的SDK。

	（4）物料APP及静态库源码 ：WBBladesDemoApp.app及libStatic.a的源码。

	（5）Release版APP：WBBladesDemoApp.app打出来的Release版APP，体积分析结果的参照物。

## 如何贡献&反馈问题
我们诚挚地希望开发者提出宝贵的意见和建议，开发者可以通过提交PR或者Issue来反馈建议和问题。

## 致谢
我们在无用类检测中使用了capstone，通过反汇编来识别函数指令中类的调用情况。同时我们也对capstone做了部分修改，如果开发者想使用capstone引擎，建议从重新下载全新的capstone代码。最后感谢capstone为我们提供了非常优秀的反汇编能力。

GitHub地址：[https://github.com/aquynh/capstone](https://github.com/aquynh/capstone "GitHub for capstone")
