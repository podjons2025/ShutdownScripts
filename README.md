<#

# 设置每天20:30关机并显示GUI
.\ShutdownScripts.ps1 -GUIMode -ShutdownTime "20:30"

# 强制立即关机(1分钟)
.\ShutdownScripts.ps1 -ForceShutdown

# 使用默认23:00关机时间
.\ShutdownScripts.ps1 -GUIMode

ProgramData:
C:\ProgramData\ShutdownScript

# 允许的IP列表
192.168.1.0/24     # 整个C类网段
10.10.0.100        # 管理员PC
172.16.0.1-172.16.0.20  # 服务器集群

# 指定外部白名单文件
.\ShutdownScripts.ps1 -GUIMode -IPWhitelistPath "C:\ip_whitelist.txt"

.\ShutdownScripts.ps1 -guimode -IPWhitelistPath .\ip_whitelist -ShutdownTime 12:00

.\ShutdownScripts.ps1 -ForceShutdown -IPWhitelistPath  C:\Users\abc\Desktop\ExcludedIPs_List.txt

#不指定IPWhitelistPath，默认查检ExcludedIPs的IP集进行排除
.\ShutdownScripts.ps1 -guimode

<img width="420" height="319" alt="image" src="https://github.com/user-attachments/assets/83c23623-4b5b-4d4a-aca4-ca646535946b" />
