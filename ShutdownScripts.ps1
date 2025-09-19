<#

# ����ÿ��20:30�ػ�����ʾGUI
.\ShutdownScripts.ps1 -GUIMode -ShutdownTime "20:30"

# ǿ�������ػ�(1����)
.\ShutdownScripts.ps1 -ForceShutdown

# ʹ��Ĭ��23:00�ػ�ʱ��
.\ShutdownScripts.ps1 -GUIMode

ProgramData:
C:\ProgramData\ShutdownScript

# �����IP�б�
192.168.1.0/24     # ����C������
10.10.0.100        # ����ԱPC
172.16.0.1-172.16.0.20  # ��������Ⱥ

# ָ���ⲿ�������ļ�
.\ShutdownScripts.ps1 -GUIMode -IPWhitelistPath "C:\ip_whitelist.txt"

.\ShutdownScripts.ps1 -guimode -IPWhitelistPath .\ip_whitelist -ShutdownTime 12:00

.\ShutdownScripts.ps1 -ForceShutdown -IPWhitelistPath  C:\Users\cti\Desktop\ExcludedIPs_List.txt

#��ָ��IPWhitelistPath��Ĭ�ϲ��ExcludedIPs �����IP�������ų�
.\ShutdownScripts.ps1 -guimode

#>


#requires -Version 3
param(
    [Parameter(HelpMessage = "IP�������ļ�·����֧��CIDR/��Χ��")]
    [string]$IPWhitelistPath,
    [switch]$ForceShutdown,
    [switch]$GUIMode,
    [Parameter(HelpMessage = "���üƻ��ػ���ʱ�䣨��ʽ��HH:mm������23:30��")]
    [ValidateScript({
        if ($_ -match '^([01]?[0-9]|2[0-3]):([0-5][0-9])$') {
            $true
        } else {
            throw "��������Ч��HH:mm��ʽʱ�䣬����23:30"
        }
    })]
    [string]$ShutdownTime = "23:00"
)

#region ����
$script:ENTERPRISE_CONFIG = @{
    GracePeriod       = 600
    CriticalPeriod    = 60
    ExcludedIPs       = @()  # Ĭ�ϰ�����
    StateFile         = "$env:ProgramData\ShutdownScript\ShutdownState.dat"
    CancelStateFile   = "$env:ProgramData\ShutdownScript\CancelState.dat" # ����ȡ��״̬�ļ�
    LogPath           = "$env:ProgramData\ShutdownScript\Logs"
    LogRetentionDays  = 30
    MinDiskSpaceMB    = 50
    Style = @{
        PrimaryColor   = "#004B8D"
        SecondaryColor = "#F5F5F5"
        DangerColor    = "#C8102E"
        FontFamily     = "΢���ź�"
    }
}
#endregion

#region ȫ��������
$global:LockFile = "$env:ProgramData\ShutdownScript\New-ScriptLock.lock"
$global:LockFileStream = $null
#endregion

#region IP�����������߼�
function ConvertTo-IPv4Number {
    param([string]$ip)
    try {
        $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
        [Array]::Reverse($bytes)
        [BitConverter]::ToUInt32($bytes, 0)
    } catch {
        #Write-Log "��ЧIP��ʽ��$ip" -Level Warn
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
            Write-Log "���ļ����ذ�������$IPWhitelistPath����$($whitelist.Count)������" -Level Info
        } else {
            $whitelist = $script:ENTERPRISE_CONFIG.ExcludedIPs
            Write-Log "ʹ��Ĭ�ϰ���������$($whitelist.Count)������" -Level Info
        }
    } catch {
        Write-Log "���ذ�����ʧ�ܣ�$_" -Level Error
    }
    return $whitelist
}
#endregion

#region ʱ�����
$timeParts = $ShutdownTime -split ':'
$hour = [int]$timeParts[0]
$minute = [int]$timeParts[1]

if ($hour -lt 0 -or $hour -gt 23) {
    Write-Host "����Сʱ������0-23֮��" -ForegroundColor Red
    exit 1
}
if ($minute -lt 0 -or $minute -gt 59) {
    Write-Host "���󣺷��ӱ�����0-59֮��" -ForegroundColor Red
    exit 1
}
#endregion

#region STAģʽ���
if (-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
    Write-Host "���󣺱���ʹ��STAģʽ���У���ʹ����������������`npowershell -STA -File $($MyInvocation.MyCommand.Path) [����]" -ForegroundColor Red
    exit 1
}
#endregion

#region ��־����
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
        # ��־��¼ʧ��ʱ��Ĭ����
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

#region ȫ���ļ�������
function New-GlobalLock {
    param([int]$TimeoutSeconds = 3)
    
    # ȷ����Ŀ¼����
    $lockDir = [System.IO.Path]::GetDirectoryName($global:LockFile)
    if (-not (Test-Path $lockDir)) {
        New-Item -ItemType Directory -Path $lockDir -Force | Out-Null
    }

    # �Ľ�1: �������ļ���������Ч��
    if (Test-Path $global:LockFile) {
        try {
            $content = Get-Content $global:LockFile -ErrorAction Stop
            $oldPid = [int]::Parse($content[0])
            
            # �������Ƿ���������
            $process = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
            if (-not $process) {
                #Write-Log "������Ч���ļ������� $oldPid ����ֹ��" -Level Info
                Remove-Item $global:LockFile -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            # �ļ���ȡʧ��ʱֱ��ɾ��
            Remove-Item $global:LockFile -Force -ErrorAction SilentlyContinue
        }
    }

    $startTime = [DateTime]::Now
    $lockAcquired = $false
    
    while (-not $lockAcquired) {
        try {
            # ����������ģʽ�����ļ�
            $global:LockFileStream = [System.IO.File]::Open(
                $global:LockFile,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            
            # д�뵱ǰ����ID
            $writer = [System.IO.StreamWriter]::new($global:LockFileStream)
            $writer.WriteLine($PID)
            $writer.Flush()
            
            $lockAcquired = $true
            #Write-Log "�ɹ���ȡȫ����" -Level Info
            
            # ע���˳��¼�������
            Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
                if ($global:LockFileStream) {
                    $global:LockFileStream.Close()
                    $global:LockFileStream.Dispose()
                    $global:LockFileStream = $null
                    Remove-Item $global:LockFile -Force -ErrorAction SilentlyContinue
                    #Write-Log "���ͷ�ȫ����" -Level Info
                }
            } | Out-Null
        }
        catch [System.IO.IOException] {
            # �����ѵȴ�ʱ��
            $elapsed = ([DateTime]::Now - $startTime).TotalSeconds
            
            # ����Ƿ�ʱ
            if ($elapsed -ge $TimeoutSeconds) {
                #Write-Log "��ȡȫ������ʱ���ȴ�${TimeoutSeconds}�룩���˳��ű�" -Level Warn
                return $false
            }
            
            # �ȴ�һ��ʱ��������
            Start-Sleep -Milliseconds 500
        }
        catch {
            #Write-Log "��ȡȫ����ʱ����$_" -Level Error
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
    #Write-Log "ǿ������ȫ����" -Level Info
}
#endregion

#region ״̬����
class ShutdownState {
    static [void] SetSchedule([datetime]$scheduleTime) {
        try {
            $stateData = @{
                ScheduleTime = $scheduleTime
                CreatedAt    = (Get-Date)
            }
            $stateData | Export-Clixml -Path $script:ENTERPRISE_CONFIG.StateFile -Force
           #Write-Log "���ùػ��ƻ���$scheduleTime" -Level Info
        }
        catch {
            #Write-Log "����״̬�ļ�ʧ�ܣ�$_" -Level Error
        }
    }

    static [bool] HasActiveSchedule() {
        try {
            if (-not (Test-Path $script:ENTERPRISE_CONFIG.StateFile)) {
                return $false
            }
            
            $state = Import-Clixml -Path $script:ENTERPRISE_CONFIG.StateFile
            $now = Get-Date
            
            # �Ľ�1: ���ƻ��Ƿ��ѹ��ڣ�����24Сʱ��
            if ($state.ScheduleTime -lt $now) {
                #Write-Log "������ڹػ��ƻ�" -Level Info
                [ShutdownState]::ClearSchedule()
                return $false
            }
            
            # �Ľ�2: ��鴴�������Ƿ����
            if ($state.CreatedAt.Date -ne $now.Date) {
                #Write-Log "����ǽ��մ����ļƻ�" -Level Info
                [ShutdownState]::ClearSchedule()
                return $false
            }
            
            return $true
        }
        catch {
            #Write-Log "��ȡ״̬�ļ�ʧ�ܣ�$_" -Level Error
            [ShutdownState]::ClearSchedule()
            return $false
        }
    }

    static [void] ClearSchedule() {
        try {
            if (Test-Path $script:ENTERPRISE_CONFIG.StateFile) {
                Remove-Item -Path $script:ENTERPRISE_CONFIG.StateFile -Force
                #Write-Log "������ػ��ƻ�״̬" -Level Info
            }
        }
        catch {
            #Write-Log "���״̬�ļ�ʧ�ܣ�$_" -Level Error
        }
    }
}

# ������ȡ��״̬����
class CancelState {
    static [bool] ShouldCancelToday() {
        $cancelFile = $script:ENTERPRISE_CONFIG.CancelStateFile
        $now = [DateTime]::Now
        
        # ����ȡ����Чʱ��� (22:00 - 23:00)
        $startCancelPeriod = Get-Date -Hour 22 -Minute 0 -Second 0
        $endCancelPeriod = Get-Date -Hour 23 -Minute 0 -Second 0
        
        # �����ǰʱ���ѹ�23:00�����ȡ��״̬
        if ($now -ge $endCancelPeriod) {
            if (Test-Path $cancelFile) {
                Remove-Item $cancelFile -Force -ErrorAction SilentlyContinue
                #Write-Log "��������ڵ�ȡ��״̬�ļ�" -Level Info
            }
            return $false
        }
        
        # ���ȡ��״̬�ļ�
        if (Test-Path $cancelFile) {
            try {
                $cancelTime = [DateTime]::Parse((Get-Content $cancelFile))
                #Write-Log "��⵽ȡ����¼��$cancelTime" -Level Info
                
                # ����Ƿ��ڵ������Чȡ��ʱ�����
                if ($cancelTime.Date -eq $now.Date -and $cancelTime -ge $startCancelPeriod) {
                    #Write-Log "��⵽����22:00֮���ȡ����¼���˳��ű�" -Level Info
                    return $true
                }
            }
            catch {
                #Write-Log "����ȡ��״̬�ļ�ʧ�ܣ�$_" -Level Error
                Remove-Item $cancelFile -Force -ErrorAction SilentlyContinue
            }
        }
        return $false
    }

    static [void] RecordCancel() {
        $cancelFile = $script:ENTERPRISE_CONFIG.CancelStateFile
        $now = [DateTime]::Now
        
        # ����ȡ����Чʱ��� (22:00 - 23:00)
        $startCancelPeriod = Get-Date -Hour 22 -Minute 0 -Second 0
        $endCancelPeriod = Get-Date -Hour 23 -Minute 0 -Second 0
        
        # ֻ����Чʱ����ڼ�¼ȡ��
        if ($now -ge $startCancelPeriod -and $now -lt $endCancelPeriod) {
            try {
                $dir = [System.IO.Path]::GetDirectoryName($cancelFile)
                if (-not (Test-Path $dir)) {
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                }
                $now.ToString("o") | Out-File $cancelFile -Force
                #Write-Log "��¼ȡ���ػ��¼�" -Level Info
            }
            catch {
                #Write-Log "��¼ȡ���¼�ʧ�ܣ�$_" -Level Error
            }
        }
    }
}
#endregion

#region �ػ�������
class EnterpriseShutdownController {
    static [void] ScheduleWithCheck([int]$seconds) {
        if ([ShutdownState]::HasActiveSchedule()) {
            return
        }

        try {
            shutdown /s /f /t $seconds | Out-Null
            [ShutdownState]::SetSchedule((Get-Date).AddSeconds($seconds))
            Write-Log "�Ѱ���ϵͳ�ػ���${seconds}���" -Level Info
        }
        catch {
            #Write-Log "���Źػ�ʧ�ܣ�$_" -Level Error
            throw
        }
    }

    static [void] SafeAbort() {
        try {
            shutdown /a | Out-Null
            [ShutdownState]::ClearSchedule()
            #Write-Log "��ȡ���ػ��ƻ�" -Level Info
        }
        catch {
            #Write-Log "ȡ���ػ�ʧ�ܣ�$_" -Level Error
            throw
        }
    }
}
#endregion

#region GUI����
function Show-EnterpriseDialog {
    param(
        [ValidateSet("Warning","Critical")]
        [string]$Phase,
        [datetime]$CustomTime = [datetime]::MinValue
    )

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop

    $script:baseTime = [DateTime]::Now
    $window = New-Object Windows.Window
    $window.Title = "�ն˹ػ�֪ͨ"
    $window.Width = 380
    $window.Height = 240
    $window.WindowStartupLocation = "CenterScreen"
    $window.Background = $script:ENTERPRISE_CONFIG.Style.SecondaryColor
    $window.FontFamily = $script:ENTERPRISE_CONFIG.Style.FontFamily
    $window.ResizeMode = "NoResize"

    # ��ʼ����־����
    $script:shutdownPerformed = $false
    $script:cancelRequested = $false
    $script:countdownEnded = $false  # ������־������ʱ����

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

    # ͷ��
    $header = New-Object Windows.Controls.Border -Property @{
        Background  = $script:ENTERPRISE_CONFIG.Style.PrimaryColor
        Padding     = "10"
    }
    $headerText = New-Object Windows.Controls.TextBlock -Property @{
        Text        = if ($Phase -eq "Warning") { "�ƻ��ػ�֪ͨ" } else { "�ػ�����" }
        Foreground  = "White"
        FontSize    = 20
        FontWeight  = "Bold"
    }
    $header.Child = $headerText
    $grid.Children.Add($header)
    [Windows.Controls.Grid]::SetRow($header, 0)

    # ��������
    $content = New-Object Windows.Controls.StackPanel -Property @{
        Margin      = "15"
        HorizontalAlignment = "Center"
    }

    $timeText = New-Object Windows.Controls.TextBlock -Property @{
        Text        = "�ƻ��ػ�ʱ��: $($script:targetTime.ToString('HH:mm:ss'))"
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

    # ��ť����
    $buttonPanel = New-Object Windows.Controls.StackPanel -Property @{
        Orientation = "Horizontal"
        HorizontalAlignment = "Center"
        Margin      = "0,10"
    }

    $btnShutdown = New-Object Windows.Controls.Button -Property @{
        Content     = "�����ػ�"
        Width       = 100
        Height      = 28
        Background  = $script:ENTERPRISE_CONFIG.Style.DangerColor
        Foreground  = "White"
        FontWeight  = "Bold"
    }
    $buttonPanel.Children.Add($btnShutdown)

    $btnCancel = New-Object Windows.Controls.Button -Property @{
        Content     = "ȡ���ػ�"
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

    # ��ʱ��
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
                $countdown.Text = "ʣ��ʱ��: $([timespan]::FromSeconds($remainingSeconds).ToString('hh\:mm\:ss'))"
            }
            "Warning" {
                if ($remainingSeconds -ge $script:ENTERPRISE_CONFIG.GracePeriod) {
                    $hours = [math]::Floor($remaining.TotalHours)
                    $minutes = $remaining.Minutes
                    $displayText = if ($hours -gt 0) {
                        "${hours}Сʱ${minutes}����"
                    } else {
                        "${minutes}����"
                    }
                    $countdown.Text = "����ػ�����: $displayText"
                } else {
                    $countdown.Text = "ʣ�໺��ʱ��: $([timespan]::FromSeconds($remainingSeconds).ToString('hh\:mm\:ss'))"
                }
            }
        }

        if ($remaining.TotalSeconds -le 0) {
            $timer.Stop()
            $script:countdownEnded = $true  # �ؼ��޸������õ���ʱ������־
            # �Ľ����ػ�ǰ��������״̬�ļ�
            [ShutdownState]::ClearSchedule()
            [EnterpriseShutdownController]::ScheduleWithCheck(0)
            Write-Log "����ʱ������ϵͳִ�йػ�" -Level Info
            $window.Close()
        }
    })

    # ��ť�¼�
    $btnShutdown.Add_Click{
        $script:shutdownPerformed = $true
        try {
            $timer.Stop()
            [EnterpriseShutdownController]::SafeAbort()
            Write-Log "�û���������ػ���ϵͳִ�йػ�" -Level Info
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
            Write-Log "�û�ȡ���ػ�" -Level Info
            
            # ��¼ȡ���¼�������Чʱ����ڣ�
            [CancelState]::RecordCancel()
        }
        finally {
            $window.Close()
        }
    }
    
    # ���ڹرմ��� 
    $window.Add_Closed({
        $timer.Stop()
        # �ؼ��޸������ڷǵ���ʱ������δִ�йػ�/ȡ������ʱ����ȡ��
        if (-not $script:countdownEnded -and -not $script:shutdownPerformed -and -not $script:cancelRequested) {
            try {
                [EnterpriseShutdownController]::SafeAbort()
                Write-Log "���ڹر� ȡ���ػ�" -Level Info
                
                # ��¼ȡ���¼�������Чʱ����ڣ�
                [CancelState]::RecordCancel()
            }
            catch {
                # �����쳣
            }
        }
    })
            
    # ������ʾ
    #Write-Log "��ʾGUI�Ի��򣬽׶Σ�$Phase��Ŀ��ʱ�䣺$($script:targetTime)" -Level Info
    $timer.Start()
    $window.ShowDialog() | Out-Null
}
#endregion

#region ������
try {	
    # ==== ȫ������飨����ִ�У�====
    if (-not (New-GlobalLock -TimeoutSeconds 3)) {
        #Write-Log "����ʵ�����У��˳��ű�" -Level Info
        exit 1
    }
    
    # ==== ���������ȡ��״̬ ====
    if ([CancelState]::ShouldCancelToday()) {
        #Write-Log "��⵽��Чȡ����¼���˳��ű�" -Level Info
        exit 0
    }
    
    # ���ذ�����
    $whitelist = Load-IPWhitelist
    $currentIPs = (Get-NetIPAddress | Where-Object { 
        $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' 
    }).IPAddress

    # ���������
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
        #Write-Log "IP $ip �ڰ������У��˳��ű�" -Level Info
        exit 
    }

    Write-Log "�ű�����������: ForceShutdown=$ForceShutdown, GUIMode=$GUIMode, ShutdownTime=$ShutdownTime, IPWhitelistPath=$IPWhitelistPath" -Level "Info"

    if ($ForceShutdown) {
        # �Ľ���ǿ�ƹػ�ǰ�����״̬
        [ShutdownState]::ClearSchedule()
        [EnterpriseShutdownController]::ScheduleWithCheck($script:ENTERPRISE_CONFIG.CriticalPeriod)
        Write-Log "ǿ�������ػ���1���ӻ��壩" -Level Info
        
        # ����GUIģʽ����ʾ�Ի���
        if ($GUIMode) {
            Show-EnterpriseDialog -Phase "Critical"
        }
        exit
    }

    # �Ľ���״̬�������Զ������߼�
    if ([ShutdownState]::HasActiveSchedule()) {
        #Write-Log "���л�ػ��ƻ����˳��ű�" -Level Info
        exit
    }

    $baseTime = [DateTime]::Now
    $targetTime = $baseTime.Date.AddHours($hour).AddMinutes($minute)
    if ($targetTime -le $baseTime) { 
        $targetTime = $targetTime.AddDays(1) 
    }

    $totalSeconds = ($targetTime - $baseTime).TotalSeconds
    [EnterpriseShutdownController]::ScheduleWithCheck($totalSeconds)
    #Write-Log "�����ùػ��ƻ���$targetTime (${totalSeconds}���)" -Level Info
    
    if ($GUIMode) {
        Show-EnterpriseDialog -Phase "Warning" -CustomTime $targetTime
    }
	
}
catch {
    Write-Log "δ������쳣: $_" -Level Error
    Write-Log "��������: $($_.Exception.StackTrace)" -Level Error
    exit 1
}
finally {
    # ȷ���쳣�˳�ʱ������
    Remove-GlobalLock
}
#endregion