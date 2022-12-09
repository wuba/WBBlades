
[简体中文](README-zh.md)|[English](README.md)

## Introduction

WBBlades is a tool set based on `Mach-O` file parsing, including useless code detection (supports `OC` and `Swift`), package size analysis (supports a single static library/dynamic library), point-to-point crash analysis ( analyse system crash log, based on symbol file and without symbol files). It mainly uses __Text assembly code analysis, architecture extraction, DYSM file stripping, symbol table stripping, crash file (ips) analysis technology.Support big method/small method parsing and iOS 15 above about dyld_chained_Fixups processing.

Version 3.0 implements a comprehensive visual implementation of the toolset based on the original command-line-based operation of the above tools, and is designed for R&D efficiency improvement. In addition, in the analysis of difficult crashes, for some crashes that are not easy to reproduce and cannot be collected by general tools (the app process is directly killed by the operating system), a point-to-point crash analysis is provided.

## Installation

```
$ git clone https://github.com/wuba/WBBlades.git
$ cd WBBlades
$ pod install
```

### Usage of Visualization Tool
Target selects "WBBladesCrashApp".

Click the button on the left function area, select a tool such as Useless Classes Detection,Application Size Analysis,etc., and operate according to the prompts in the tool, and the result will be output to the text box;

### Usage for Mac Command Line
Target selects "WBBlades"，Compile and build to generate command line tools
Copy the generated product "blades" to /usr/local/bin，as follows：
sudo cp ${Your_BUILD_DIR}/blades /usr/local/bin


- Unused Code Detection ObjC & Swift

   `$ blades -unused xxx.app -from xxx.a xxx.a ....`
   
	> -from indicating that only the unused code in the following static libraries is analyzed. Without this parameter, the default is all classes in the APP.
   
- App Size Analysis (Directly measure the size of .a or .framework after linking)

  `$ blades -size xxx.a xxx.framework ....`
  
  > Supporting input a folder path, all static libraries under the folder will be analyzed.
  
- Log Recovery without dSYM File (In the case of missing dSYM file, try `ObjC` crash stack symbolization, `Swift` is not supported)

  `$ blades -symbol xxx.app -logPath xxx.ips`

## Tool Features

### Unused code (unused class) detection support range

| Description                     | Support | Code Example                                     |
| :----------------------- | :----------: | :------------------------------------------- |
| ObjC classes's static call       |      ✅       | `[MyClass new]`                              |
| ObjC classes's dynamic call           |      ✅       | `NSClassFromString(@"MyClass")`              |
| ObjC dynamic call througn string concatenation    |      ❌       | `NSClassFromString(@"My" + @"Class")`        |
| ObjC load method         |      ✅       | `+load{...} `                                |
| ObjC & Swift being inherited       |      ✅       | `SomClass : MyClass`                         |
| ObjC & Swift being properties      |      ✅       | `@property (strong,atomic) MyClass *obj;`    |
| Swift class direct call         |      ✅       | `MyClass.init()`                             |
| Swift call using runtime    |      ❌       | `objc_getClass("Demo.MyClass")`              |
| Swift generic parameters           |      ✅       | `SomeClass<MyClass>.init()`                  |
| Swfit class dynamic call in ObjC   |      ✅       | `NSClassFromString("Demo.MyClass")`          |
| Swift type declaration in the container |      ❌       | `var array:[MyClass]`                        |
| Swift multiple nesting           |      ✅       | ` class SomeClass {class MyClass {...} ...}` |

### App Size Analysis Tool

Supports quick detection of the linked size of a static library. No need to compile and link. **For example: If you want to know how much app size will increase when an SDK is imported or updated, you can use `blades -size` to estimate the size**, without the need to connect the SDK to compile and link successfully to calculate.

### Crash Log Symbolization Tool Without dSYM File

In the case of losing the dSYM file, try to restore the log via `blades -symbol`. **For example, in an app packaging, the dSYM file is cleared after a period of time, but the app file is retained. In this case, you can consider using blades for symbolization. **Before using the tool, pay attention to a few points:

- If your app is a debug package or a package that does not strip the symbol table, you can use `dsymutil app -o xx.dSYM `to extract the symbol table. Then use the symbol table to symbolize the log.

- This tool only supports ObjC, and its principle is to determine the function of the crash by analyzing the address of the ObjC method in Mach-O. Therefore, it is not suitable for Swfit, C, and C++. In addition, tools are not omnipotent, and are only used as emergency supplementary technical means. In daily situations, it is recommended to use symbol tables for log symbolization.


## Contributing & Feedback

We sincerely hope that developers can provide valuable comments and suggestions, and developers can provide feedback on suggestions and problems by submitting PR or Issue.

## Related Technical Articles

- [58tongcheng Size Analysis and Statistics for iOS Client Components](https://blog.csdn.net/csdnnews/article/details/100354658/)
- [Unused Class Detection Based on Mach-O Disassembly](https://www.jianshu.com/p/c41ad330e81c)
- [Open Source｜WBBlades：APP Analysis Tool Set Based on Mach-O File Analysis](https://mp.weixin.qq.com/s/HWJArO5y9G20jb2pqaAQWQ)
- [The Storage Difference between Swift and ObjC from the Perspective of Mach-O](https://www.jianshu.com/p/ef0ff6ee6bc6)
- [New Approach to Swift Hook - Virtual Method Table](https://mp.weixin.qq.com/s/mjwOVdPZUlEMgLUNdT6o9g)

## Thanks

GitHub: [https://github.com/aquynh/capstone](https://github.com/aquynh/capstone "GitHub for capstone")

GitHub: [https://github.com/Sunnyyoung/SYFlatButton](https://github.com/Sunnyyoung/SYFlatButton "GitHub for SYFlatButton") 

GitHub: [https://github.com/alexrozanski/PXListView](https://github.com/alexrozanski/PXListView "GitHub for PXListView")

GitHub: [https://github.com/steventroughtonsmith/cartool](https://github.com/steventroughtonsmith/cartool "cartool")

DWARF: [https://www.prevanders.net/dwarf.html#releases](https://www.prevanders.net/dwarf.html#releases "Source Code for DWARF") 

GitHub:
[https://github.com/nygard/class-dump](https://github.com/nygard/class-dump "GitHub for class-dump")
  
