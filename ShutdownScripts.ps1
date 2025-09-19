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

.\ShutdownScripts.ps1 -ForceShutdown -IPWhitelistPath  C:\Users\cti\Desktop\ExcludedIPs_List.txt

#不指定IPWhitelistPath，默认查检ExcludedIPs 数组的IP集进行排除
.\ShutdownScripts.ps1 -guimode

#>


#requires -Version 3
param(
    [Parameter(HelpMessage = "IP白名单文件路径（支持CIDR/范围）")]
    [string]$IPWhitelistPath,
    [switch]$ForceShutdown,
    [switch]$GUIMode,
    [Parameter(HelpMessage = "设置计划关机的时间（格式：HH:mm，例如23:30）")]
    [ValidateScript({
        if ($_ -match '^([01]?[0-9]|2[0-3]):([0-5][0-9])$') {
            $true
        } else {
            throw "请输入有效的HH:mm格式时间，例如23:30"
        }
    })]
    [string]$ShutdownTime = "23:00"
)

#region 配置
$script:ENTERPRISE_CONFIG = @{
    GracePeriod       = 600
    CriticalPeriod    = 60
    ExcludedIPs       = @()  # 默认白名单
    StateFile         = "$env:ProgramData\ShutdownScript\ShutdownState.dat"
    CancelStateFile   = "$env:ProgramData\ShutdownScript\CancelState.dat" # 新增取消状态文件
    LogPath           = "$env:ProgramData\ShutdownScript\Logs"
    LogRetentionDays  = 30
    MinDiskSpaceMB    = 50
    Style = @{
        PrimaryColor   = "#004B8D"
        SecondaryColor = "#F5F5F5"
        DangerColor    = "#C8102E"
        FontFamily     = "微软雅黑"
    }
}
#endregion

#region 全局锁变量
$global:LockFile = "$env:ProgramData\ShutdownScript\New-ScriptLock.lock"
$global:LockFileStream = $null
#endregion

#region IP白名单处理逻辑
function ConvertTo-IPv4Number {
    param([string]$ip)
    try {
        $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
        [Array]::Reverse($bytes)
        [BitConverter]::ToUInt32($bytes, 0)
    } catch {
        #Write-Log "无效IP格式：$ip" -Level Warn
        return $null
    }
}

function Test-IPInCIDR {
    param($ip, $cidr)
    $network, [int]$mask = $cidr -split '/'
    $ipNum = ConvertTo-IPv4Number $ip
    $networkNum = ConvertTo-IPv4Number $network
    if (-not $ipNum -or -not $networkNum) { return $false }
    $maskNum = [UInt32]::MaxValue -shl (32 - $mask)
    ($ipNum -band $maskNum) -eq ($networkNum -band $maskNum)
}

function Test-IPInRange {
    param($ip, $start, $end)
    $ipNum = ConvertTo-IPv4Number $ip
    $startNum = ConvertTo-IPv4Number $start
    $endNum = ConvertTo-IPv4Number $end
    if (-not $ipNum -or -not $startNum -or -not $endNum) { return $false }
    $ipNum -ge $startNum -and $ipNum -le $endNum
}

function Load-IPWhitelist {
    $whitelist = @()
    try {
        if ($IPWhitelistPath -and (Test-Path $IPWhitelistPath)) {
            $rawContent = Get-Content $IPWhitelistPath | Where-Object {
                $_ -notmatch '^\s*#' -and $_.Trim() -ne ''
            }
            $whitelist = $rawContent | ForEach-Object { $_.Split('#')[0].Trim() }
            Write-Log "从文件加载白名单：$IPWhitelistPath，共$($whitelist.Count)条规则" -Level Info
        } else {
            $whitelist = $script:ENTERPRISE_CONFIG.ExcludedIPs
            Write-Log "使用默认白名单，共$($whitelist.Count)条规则" -Level Info
        }
    } catch {
        Write-Log "加载白名单失败：$_" -Level Error
    }
    return $whitelist
}
#endregion

#region 时间解析
$timeParts = $ShutdownTime -split ':'
$hour = [int]$timeParts[0]
$minute = [int]$timeParts[1]

if ($hour -lt 0 -or $hour -gt 23) {
    Write-Host "错误：小时必须在0-23之间" -ForegroundColor Red
    exit 1
}
if ($minute -lt 0 -or $minute -gt 59) {
    Write-Host "错误：分钟必须在0-59之间" -ForegroundColor Red
    exit 1
}
#endregion

#region STA模式检查
if (-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
    Write-Host "错误：必须使用STA模式运行！请使用以下命令启动：`npowershell -STA -File $($MyInvocation.MyCommand.Path) [参数]" -ForegroundColor Red
    exit 1
}
#endregion

#region 日志管理
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    
    try {
        $logDir = $script:ENTERPRISE_CONFIG.LogPath

        if (Test-Path $logDir) {
            $drive = Get-PSDrive -Name ($logDir.Substring(0,1)) -ErrorAction SilentlyContinue
            if ($drive -and $drive.Free -lt ($script:ENTERPRISE_CONFIG.MinDiskSpaceMB * 1MB)) {
                return
            }
        }

        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        
        $logFile = Join-Path $logDir "Shutdown_$(Get-Date -Format 'yyyyMMdd').log"
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        Add-Content -Path $logFile -Value "[$timestamp] [$Level] $Message" -Encoding UTF8
    }
    catch {
        # 日志记录失败时静默处理
    }
}

function Initialize-Logging {
    try {
        $logDir = $script:ENTERPRISE_CONFIG.LogPath
        if (Test-Path $logDir) {
            $limit = (Get-Date).AddDays(-$script:ENTERPRISE_CONFIG.LogRetentionDays)
            Get-ChildItem $logDir -Filter "Shutdown_*.log" | 
            Where-Object { $_.LastWriteTime -lt $limit } | 
            Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
    catch {}
}

Initialize-Logging
#endregion

#region 全局文件锁控制
function New-GlobalLock {
    param([int]$TimeoutSeconds = 3)
    
    # 确保锁目录存在
    $lockDir = [System.IO.Path]::GetDirectoryName($global:LockFile)
    if (-not (Test-Path $lockDir)) {
        New-Item -ItemType Directory -Path $lockDir -Force | Out-Null
    }

    # 改进1: 检查旧锁文件并清理无效锁
    if (Test-Path $global:LockFile) {
        try {
            $content = Get-Content $global:LockFile -ErrorAction Stop
            $oldPid = [int]::Parse($content[0])
            
            # 检查进程是否仍在运行
            $process = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
            if (-not $process) {
                #Write-Log "清理无效锁文件（进程 $oldPid 已终止）" -Level Info
                Remove-Item $global:LockFile -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            # 文件读取失败时直接删除
            Remove-Item $global:LockFile -Force -ErrorAction SilentlyContinue
        }
    }

    $startTime = [DateTime]::Now
    $lockAcquired = $false
    
    while (-not $lockAcquired) {
        try {
            # 尝试以排他模式打开锁文件
            $global:LockFileStream = [System.IO.File]::Open(
                $global:LockFile,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            
            # 写入当前进程ID
            $writer = [System.IO.StreamWriter]::new($global:LockFileStream)
            $writer.WriteLine($PID)
            $writer.Flush()
            
            $lockAcquired = $true
            #Write-Log "成功获取全局锁" -Level Info
            
            # 注册退出事件清理锁
            Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
                if ($global:LockFileStream) {
                    $global:LockFileStream.Close()
                    $global:LockFileStream.Dispose()
                    $global:LockFileStream = $null
                    Remove-Item $global:LockFile -Force -ErrorAction SilentlyContinue
                    #Write-Log "已释放全局锁" -Level Info
                }
            } | Out-Null
        }
        catch [System.IO.IOException] {
            # 计算已等待时间
            $elapsed = ([DateTime]::Now - $startTime).TotalSeconds
            
            # 检查是否超时
            if ($elapsed -ge $TimeoutSeconds) {
                #Write-Log "获取全局锁超时（等待${TimeoutSeconds}秒），退出脚本" -Level Warn
                return $false
            }
            
            # 等待一段时间再重试
            Start-Sleep -Milliseconds 500
        }
        catch {
            #Write-Log "获取全局锁时出错：$_" -Level Error
            return $false
        }
    }
    
    return $true
}

function Remove-GlobalLock {
    if ($global:LockFileStream) {
        $global:LockFileStream.Close()
        $global:LockFileStream.Dispose()
        $global:LockFileStream = $null
    }
    Remove-Item $global:LockFile -Force -ErrorAction SilentlyContinue
    #Write-Log "强制清理全局锁" -Level Info
}
#endregion

#region 状态管理
class ShutdownState {
    static [void] SetSchedule([datetime]$scheduleTime) {
        try {
            $stateData = @{
                ScheduleTime = $scheduleTime
                CreatedAt    = (Get-Date)
            }
            $stateData | Export-Clixml -Path $script:ENTERPRISE_CONFIG.StateFile -Force
           #Write-Log "设置关机计划：$scheduleTime" -Level Info
        }
        catch {
            #Write-Log "保存状态文件失败：$_" -Level Error
        }
    }

    static [bool] HasActiveSchedule() {
        try {
            if (-not (Test-Path $script:ENTERPRISE_CONFIG.StateFile)) {
                return $false
            }
            
            $state = Import-Clixml -Path $script:ENTERPRISE_CONFIG.StateFile
            $now = Get-Date
            
            # 改进1: 检查计划是否已过期（超过24小时）
            if ($state.ScheduleTime -lt $now) {
                #Write-Log "清理过期关机计划" -Level Info
                [ShutdownState]::ClearSchedule()
                return $false
            }
            
            # 改进2: 检查创建日期是否今天
            if ($state.CreatedAt.Date -ne $now.Date) {
                #Write-Log "清理非今日创建的计划" -Level Info
                [ShutdownState]::ClearSchedule()
                return $false
            }
            
            return $true
        }
        catch {
            #Write-Log "读取状态文件失败：$_" -Level Error
            [ShutdownState]::ClearSchedule()
            return $false
        }
    }

    static [void] ClearSchedule() {
        try {
            if (Test-Path $script:ENTERPRISE_CONFIG.StateFile) {
                Remove-Item -Path $script:ENTERPRISE_CONFIG.StateFile -Force
                #Write-Log "已清除关机计划状态" -Level Info
            }
        }
        catch {
            #Write-Log "清除状态文件失败：$_" -Level Error
        }
    }
}

# 新增：取消状态管理
class CancelState {
    static [bool] ShouldCancelToday() {
        $cancelFile = $script:ENTERPRISE_CONFIG.CancelStateFile
        $now = [DateTime]::Now
        
        # 定义取消有效时间段 (22:00 - 23:00)
        $startCancelPeriod = Get-Date -Hour 22 -Minute 0 -Second 0
        $endCancelPeriod = Get-Date -Hour 23 -Minute 0 -Second 0
        
        # 如果当前时间已过23:00，清除取消状态
        if ($now -ge $endCancelPeriod) {
            if (Test-Path $cancelFile) {
                Remove-Item $cancelFile -Force -ErrorAction SilentlyContinue
                #Write-Log "已清除过期的取消状态文件" -Level Info
            }
            return $false
        }
        
        # 检查取消状态文件
        if (Test-Path $cancelFile) {
            try {
                $cancelTime = [DateTime]::Parse((Get-Content $cancelFile))
                #Write-Log "检测到取消记录：$cancelTime" -Level Info
                
                # 检查是否在当天的有效取消时间段内
                if ($cancelTime.Date -eq $now.Date -and $cancelTime -ge $startCancelPeriod) {
                    #Write-Log "检测到当天22:00之后的取消记录，退出脚本" -Level Info
                    return $true
                }
            }
            catch {
                #Write-Log "解析取消状态文件失败：$_" -Level Error
                Remove-Item $cancelFile -Force -ErrorAction SilentlyContinue
            }
        }
        return $false
    }

    static [void] RecordCancel() {
        $cancelFile = $script:ENTERPRISE_CONFIG.CancelStateFile
        $now = [DateTime]::Now
        
        # 定义取消有效时间段 (22:00 - 23:00)
        $startCancelPeriod = Get-Date -Hour 22 -Minute 0 -Second 0
        $endCancelPeriod = Get-Date -Hour 23 -Minute 0 -Second 0
        
        # 只在有效时间段内记录取消
        if ($now -ge $startCancelPeriod -and $now -lt $endCancelPeriod) {
            try {
                $dir = [System.IO.Path]::GetDirectoryName($cancelFile)
                if (-not (Test-Path $dir)) {
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                }
                $now.ToString("o") | Out-File $cancelFile -Force
                #Write-Log "记录取消关机事件" -Level Info
            }
            catch {
                #Write-Log "记录取消事件失败：$_" -Level Error
            }
        }
    }
}
#endregion

#region 关机控制器
class EnterpriseShutdownController {
    static [void] ScheduleWithCheck([int]$seconds) {
        if ([ShutdownState]::HasActiveSchedule()) {
            return
        }

        try {
            shutdown /s /f /t $seconds | Out-Null
            [ShutdownState]::SetSchedule((Get-Date).AddSeconds($seconds))
            Write-Log "已安排系统关机（${seconds}秒后）" -Level Info
        }
        catch {
            #Write-Log "安排关机失败：$_" -Level Error
            throw
        }
    }

    static [void] SafeAbort() {
        try {
            shutdown /a | Out-Null
            [ShutdownState]::ClearSchedule()
            #Write-Log "已取消关机计划" -Level Info
        }
        catch {
            #Write-Log "取消关机失败：$_" -Level Error
            throw
        }
    }
}
#endregion

#region GUI界面
function Show-EnterpriseDialog {
    param(
        [ValidateSet("Warning","Critical")]
        [string]$Phase,
        [datetime]$CustomTime = [datetime]::MinValue
    )

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop

    $script:baseTime = [DateTime]::Now
    $window = New-Object Windows.Window
    $window.Title = "终端关机通知"
    $window.Width = 380
    $window.Height = 240
    $window.WindowStartupLocation = "CenterScreen"
    $window.Background = $script:ENTERPRISE_CONFIG.Style.SecondaryColor
    $window.FontFamily = $script:ENTERPRISE_CONFIG.Style.FontFamily
    $window.ResizeMode = "NoResize"

    # 初始化标志变量
    $script:shutdownPerformed = $false
    $script:cancelRequested = $false
    $script:countdownEnded = $false  # 新增标志：倒计时结束

    if ($Phase -eq "Critical") {
        $script:targetTime = [DateTime]::Now.AddSeconds($script:ENTERPRISE_CONFIG.CriticalPeriod)
        $totalSeconds = $script:ENTERPRISE_CONFIG.CriticalPeriod
    } else {
        $script:targetTime = $CustomTime
        if ($script:targetTime -le [DateTime]::Now) { 
            $script:targetTime = $script:targetTime.AddDays(1) 
        }
        $totalSeconds = ($script:targetTime - [DateTime]::Now).TotalSeconds
    }

    $grid = New-Object Windows.Controls.Grid
    $grid.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
    $grid.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition))
    $grid.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
    $window.Content = $grid

    # 头部
    $header = New-Object Windows.Controls.Border -Property @{
        Background  = $script:ENTERPRISE_CONFIG.Style.PrimaryColor
        Padding     = "10"
    }
    $headerText = New-Object Windows.Controls.TextBlock -Property @{
        Text        = if ($Phase -eq "Warning") { "计划关机通知" } else { "关机警告" }
        Foreground  = "White"
        FontSize    = 20
        FontWeight  = "Bold"
    }
    $header.Child = $headerText
    $grid.Children.Add($header)
    [Windows.Controls.Grid]::SetRow($header, 0)

    # 内容区域
    $content = New-Object Windows.Controls.StackPanel -Property @{
        Margin      = "15"
        HorizontalAlignment = "Center"
    }

    $timeText = New-Object Windows.Controls.TextBlock -Property @{
        Text        = "计划关机时间: $($script:targetTime.ToString('HH:mm:ss'))"
        FontSize    = 16
        Margin      = "0,0,0,10"
    }
    $content.Children.Add($timeText)

    $countdown = New-Object Windows.Controls.TextBlock -Property @{
        FontSize    = 14
        Foreground  = $script:ENTERPRISE_CONFIG.Style.DangerColor
    }
    $content.Children.Add($countdown)

    $progress = New-Object Windows.Controls.ProgressBar -Property @{
        Height      = 16
        Width       = 300
        Margin      = "0,15,0,0"
        Foreground  = $script:ENTERPRISE_CONFIG.Style.DangerColor
    }
    $content.Children.Add($progress)

    $grid.Children.Add($content)
    [Windows.Controls.Grid]::SetRow($content, 1)

    # 按钮区域
    $buttonPanel = New-Object Windows.Controls.StackPanel -Property @{
        Orientation = "Horizontal"
        HorizontalAlignment = "Center"
        Margin      = "0,10"
    }

    $btnShutdown = New-Object Windows.Controls.Button -Property @{
        Content     = "立即关机"
        Width       = 100
        Height      = 28
        Background  = $script:ENTERPRISE_CONFIG.Style.DangerColor
        Foreground  = "White"
        FontWeight  = "Bold"
    }
    $buttonPanel.Children.Add($btnShutdown)

    $btnCancel = New-Object Windows.Controls.Button -Property @{
        Content     = "取消关机"
        Width       = 100
        Height      = 28
        Background  = $script:ENTERPRISE_CONFIG.Style.PrimaryColor
        Foreground  = "White"
        Margin      = "10,0,0,0"
        FontWeight  = "Bold"
    }
    $buttonPanel.Children.Add($btnCancel)

    $grid.Children.Add($buttonPanel)
    [Windows.Controls.Grid]::SetRow($buttonPanel, 2)

    # 计时器
    $timer = New-Object Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)

    $timer.Add_Tick({
        $currentTime = [DateTime]::Now
        $remaining = $script:targetTime - $currentTime
        $remainingSeconds = [math]::Max(0, $remaining.TotalSeconds)

        $totalTime = if ($Phase -eq "Critical") {
            $script:ENTERPRISE_CONFIG.CriticalPeriod
        } else {
            ($script:targetTime - $script:baseTime).TotalSeconds
        }

        $progress.Value = (($totalTime - $remainingSeconds) / $totalTime) * 100

        switch ($Phase) {
            "Critical" {
                $countdown.Text = "剩余时间: $([timespan]::FromSeconds($remainingSeconds).ToString('hh\:mm\:ss'))"
            }
            "Warning" {
                if ($remainingSeconds -ge $script:ENTERPRISE_CONFIG.GracePeriod) {
                    $hours = [math]::Floor($remaining.TotalHours)
                    $minutes = $remaining.Minutes
                    $displayText = if ($hours -gt 0) {
                        "${hours}小时${minutes}分钟"
                    } else {
                        "${minutes}分钟"
                    }
                    $countdown.Text = "距离关机还有: $displayText"
                } else {
                    $countdown.Text = "剩余缓冲时间: $([timespan]::FromSeconds($remainingSeconds).ToString('hh\:mm\:ss'))"
                }
            }
        }

        if ($remaining.TotalSeconds -le 0) {
            $timer.Stop()
            $script:countdownEnded = $true  # 关键修复：设置倒计时结束标志
            # 改进：关机前主动清理状态文件
            [ShutdownState]::ClearSchedule()
            [EnterpriseShutdownController]::ScheduleWithCheck(0)
            Write-Log "倒计时结束，系统执行关机" -Level Info
            $window.Close()
        }
    })

    # 按钮事件
    $btnShutdown.Add_Click{
        $script:shutdownPerformed = $true
        try {
            $timer.Stop()
            [EnterpriseShutdownController]::SafeAbort()
            Write-Log "用户点击立即关机，系统执行关机" -Level Info
            shutdown /s /f /t 0 | Out-Null
        }
        finally {
            $window.Close()
        }
    }

    $btnCancel.Add_Click{
        $script:cancelRequested = $true
        try {
            $timer.Stop()
            [EnterpriseShutdownController]::SafeAbort()
            Write-Log "用户取消关机" -Level Info
            
            # 记录取消事件（在有效时间段内）
            [CancelState]::RecordCancel()
        }
        finally {
            $window.Close()
        }
    }
    
    # 窗口关闭处理 
    $window.Add_Closed({
        $timer.Stop()
        # 关键修复：仅在非倒计时结束且未执行关机/取消操作时触发取消
        if (-not $script:countdownEnded -and -not $script:shutdownPerformed -and -not $script:cancelRequested) {
            try {
                [EnterpriseShutdownController]::SafeAbort()
                Write-Log "窗口关闭 取消关机" -Level Info
                
                # 记录取消事件（在有效时间段内）
                [CancelState]::RecordCancel()
            }
            catch {
                # 忽略异常
            }
        }
    })
            
    # 窗口显示
    #Write-Log "显示GUI对话框，阶段：$Phase，目标时间：$($script:targetTime)" -Level Info
    $timer.Start()
    $window.ShowDialog() | Out-Null
}
#endregion

#region 主流程
try {	
    # ==== 全局锁检查（最先执行）====
    if (-not (New-GlobalLock -TimeoutSeconds 3)) {
        #Write-Log "已有实例运行，退出脚本" -Level Info
        exit 1
    }
    
    # ==== 新增：检查取消状态 ====
    if ([CancelState]::ShouldCancelToday()) {
        #Write-Log "检测到有效取消记录，退出脚本" -Level Info
        exit 0
    }
    
    # 加载白名单
    $whitelist = Load-IPWhitelist
    $currentIPs = (Get-NetIPAddress | Where-Object { 
        $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' 
    }).IPAddress

    # 白名单检查
    $isExcluded = $false
    foreach ($ip in $currentIPs) {
        foreach ($entry in $whitelist) {
            if ($entry -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
                if (Test-IPInCIDR $ip $entry) { $isExcluded = $true; break }
            } elseif ($entry -match '(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)') {
                if (Test-IPInRange $ip $Matches[1] $Matches[2]) { $isExcluded = $true; break }
            } else {
                if ($ip -eq $entry) { $isExcluded = $true; break }
            }
        }
        if ($isExcluded) { break }
    }

    if($isExcluded) { 
        #Write-Log "IP $ip 在白名单中，退出脚本" -Level Info
        exit 
    }

    Write-Log "脚本启动，参数: ForceShutdown=$ForceShutdown, GUIMode=$GUIMode, ShutdownTime=$ShutdownTime, IPWhitelistPath=$IPWhitelistPath" -Level "Info"

    if ($ForceShutdown) {
        # 改进：强制关机前清除旧状态
        [ShutdownState]::ClearSchedule()
        [EnterpriseShutdownController]::ScheduleWithCheck($script:ENTERPRISE_CONFIG.CriticalPeriod)
        Write-Log "强制立即关机（1分钟缓冲）" -Level Info
        
        # 仅在GUI模式下显示对话框
        if ($GUIMode) {
            Show-EnterpriseDialog -Phase "Critical"
        }
        exit
    }

    # 改进：状态检查包含自动清理逻辑
    if ([ShutdownState]::HasActiveSchedule()) {
        #Write-Log "已有活动关机计划，退出脚本" -Level Info
        exit
    }

    $baseTime = [DateTime]::Now
    $targetTime = $baseTime.Date.AddHours($hour).AddMinutes($minute)
    if ($targetTime -le $baseTime) { 
        $targetTime = $targetTime.AddDays(1) 
    }

    $totalSeconds = ($targetTime - $baseTime).TotalSeconds
    [EnterpriseShutdownController]::ScheduleWithCheck($totalSeconds)
    #Write-Log "已设置关机计划：$targetTime (${totalSeconds}秒后)" -Level Info
    
    if ($GUIMode) {
        Show-EnterpriseDialog -Phase "Warning" -CustomTime $targetTime
    }
	
}
catch {
    Write-Log "未处理的异常: $_" -Level Error
    Write-Log "错误详情: $($_.Exception.StackTrace)" -Level Error
    exit 1
}
finally {
    # 确保异常退出时清理锁
    Remove-GlobalLock
}
#endregion