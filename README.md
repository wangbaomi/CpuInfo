## 获取进程的cpu占有率

使用[NtQuerySystemInformation](http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx)来获取进程的cpu占有率, 大部分都是copy网上的代码

测试时发现，NtQuerySystemInformation 在win7 64位环境下，枚举出的进程数量一直都是0，在win7 32位和win2012环境都能正常使用。

