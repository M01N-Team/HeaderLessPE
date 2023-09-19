# HeaderLessPE
## Introduction ([中文](/README_zh.md))
HeaderLessPE is a memory PE loading technique used by the Icedid Trojan. Based on this technology, we propose a new way of file-less attack using HVNC . This enhancement allows to inject HeaderLessPE into execute graphical hacking tools without limitations.
Compared to other in-memory loading techniques like MemDll, the extended HeaderLessPE has two advantages:  
- **Avoids the traditional DOS and PE headers IOC**
The DOS header and PE header are often focal points for memory scanning, requiring the use of a Profile file to erase the loaded Beacon header when using Cobalt Strike. With HeaderLessPE, you don't need to worry about this issue.  
- **Supports relocation and import tables, making it easy to convert EXEs into HeaderLessPE structures**
As long as it supports relocation and does not include structures such as Tls and delay import, it can be converted into HeaderLessPE. This can be used not only for creating Trojan memory modules but also for conveniently converting some hacking tools into HeaderLessPE for in-memory loading and execution, expanding the available attack tools.  
  
[![](image/1.png)](https://github.com/M01N-Team/HeaderLessPE/blob/master/image/1.png)
  
## TEST
tools.exe -i "desktop_name" c:\windows\system32\mspaint.exe loader.exe BrowsingHistoryView.exe

This will run the BrowsingHistoryView tool without a file on the desktop_name desktop.

[![](image/2.png)](https://github.com/M01N-Team/HeaderLessPE/blob/master/image/1.png)

Article Link：https://mp.weixin.qq.com/s?__biz=MzkyMTI0NjA3OA==&mid=2247492342&idx=1&sn=f3e7bd34d73946e294756cce75181c83&chksm=c18422e7f6f3abf168a3c11a48bee1778dc67a5e7f4e1a02fc0461af0bbe0f18476d7215194e&token=1954079270&lang=zh_CN#rd

## Reference 
1. https://github.com/strivexjun/MemoryModulePP.git
2. https://doxygen.reactos.org
3. https://github.com/hasherezade/pe-sieve.git
4. https://bbs.kanxue.com/thread-264956.htm

