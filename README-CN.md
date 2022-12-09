**简体中文** | [English](./README.md)

---

## 简介

WBBlades是基于`Mach-O`文件解析的工具集，包括App一键体检（支持`OC`和`Swift`的无用类检测）、包大小分析（支持单个静态库/动态库的包大小分析）、点对点崩溃解析（基于系统日志，支持有符号状态和无符号状态）、基于Mach-O的Class自动提取并Hook能力。主要利用了__Text汇编代码分析、架构提取、符号表剥离、dYSM文件提取、崩溃文件(ips)解析等技术手段实现，支持big method /small method 解析 以及 iOS 15以上关于  dyld_chained_fixups的处理。

