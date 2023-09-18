# HeaderLessPE
## Introduction ([English](/README.md))
扩展ICEDID使用过内存PE加载技术，使其能无文件运行一个GUI程序。
相比MemDll等内存加载技术，扩展后的HeaderLessPE有两个优点：
- **避免传统PE的DOS头、PE头特征**
DOS头和PE头经常是被内存扫描的照顾重点特征，在使用Cobalt Strike的时候常需要设置Profile文件将加载完成的Beacon头抹掉。使用HeaderLessPE就不需要担心这个问题。
- **支持重定位和导入表，能方便的将EXE转换为HeaderLessPE结构**
只要是支持重定位，不包含如：Tls、delay import等结构都能够转换为HeaderLessPE, 这样不仅可以用来做木马内存模块，还可以将一些黑客工具方便的转换为HeaderLessPE进行内存加载运行，扩展可使用的攻击工具。

[![](image/1.png)](https://github.com/M01N-Team/HeaderLessPE/blob/master/image/1.png)

## 测试
tools.exe -i "desktop_name" c:\windows\system32\mspaint.exe loader.exe ADExplorer64.exe

将会在desktop_name的桌面中无文件运行ADExplorer64工具

[![](image/2.png)](https://github.com/M01N-Team/HeaderLessPE/blob/master/image/1.png)

文章链接：


