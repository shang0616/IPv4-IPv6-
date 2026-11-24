[CmdletBinding()]
param(
    [ValidateRange(1, 3600)][int]$Seconds = 60,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'captures\campus'),
    [switch]$NoBrowser,
    [switch]$NoPause
)

function ConvertTo-CampusArgument {
    param([string]$Value)
    # Windows argv quoting: escape quotes and double backslashes before a
    # closing quote, including a directory ending with a backslash.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function New-CampusElevationArguments {
    param([string]$ScriptPath, [int]$Seconds, [string]$Directory,
          [switch]$NoBrowser, [switch]$NoPause)
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File {0} -Seconds {1} -OutputDirectory {2}' -f
        (ConvertTo-CampusArgument $ScriptPath), $Seconds, (ConvertTo-CampusArgument $Directory)
    if ($NoBrowser) { $arguments += ' -NoBrowser' }
    if ($NoPause) { $arguments += ' -NoPause' }
    return $arguments
}

function Test-CampusAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-CampusPktmon {
    param([string[]]$Arguments)
    # Windows PowerShell 5.1 turns native stderr into ErrorRecords. Preserve it,
    # then use the native exit code, including when no session is running.
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    $command = (Get-Command pktmon.exe -ErrorAction Stop).Source
    $lines = @(& $command @Arguments 2>&1)
    $code = $LASTEXITCODE
    return [pscustomobject]@{ ExitCode = $code; Output = ($lines | Out-String) }
}

function Write-CampusCommandLog {
    param([string]$Path, [string]$Operation, $Result)
    $entry = '[{0}] {1}: exit={2}{3}{4}' -f (Get-Date -Format o), $Operation,
        $Result.ExitCode, [Environment]::NewLine, $Result.Output
    Add-Content -LiteralPath $Path -Value $entry -Encoding UTF8 -ErrorAction Stop
}

function Open-CampusPortal {
    Start-Process 'http://neverssl.com' -ErrorAction Stop
}

function Wait-CampusCapture {
    param([int]$Seconds)
    Start-Sleep -Seconds $Seconds
}

function Invoke-CampusCapture {
    param([int]$Seconds, [string]$OutputDirectory, [switch]$NoBrowser)
    $ErrorActionPreference = 'Stop'
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    # Unique names avoid mixing old captures or deleting another run's output.
    $stamp = '{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss_fff'),
        ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $base = Join-Path $OutputDirectory "campus_$stamp"
    $etl = "$base.etl"
    $pcap = "$base.pcapng"
    $log = "$base.log"
    $started = $false
    $captureError = $null
    $stopError = $null

    Write-Host "输出文件: $pcap"
    Write-Host '抓取本机网卡收发的流量，也会包含网卡收到的广播/多播。'
    Write-Host '完整保存数据包；仅采集网卡组件，减少协议栈重复记录。'
    try {
        # Filters are global pktmon state. Record them without clearing the
        # user's configuration, and never stop an existing capture to start ours.
        $filters = Invoke-CampusPktmon -Arguments @('filter', 'list')
        Write-CampusCommandLog $log 'filter list (inherited configuration)' $filters
        if ($filters.ExitCode -ne 0) { throw '无法读取 pktmon 筛选器，详见日志。' }
        Write-Host $filters.Output
        Write-Host '若上方已有筛选器，本次沿用；输出不代表未命中的流量不存在。'

        $result = Invoke-CampusPktmon -Arguments @(
            'start', '--capture', '--comp', 'nics', '--type', 'flow',
            '--pkt-size', '0', '--file-size', '512', '--log-mode', 'circular',
            '--file-name', $etl
        )
        # Record ownership before any subsequent operation can fail.
        if ($result.ExitCode -eq 0) { $started = $true }
        Write-CampusCommandLog $log 'start' $result
        if (-not $started) { throw 'pktmon 启动失败；请检查权限或已有抓包会话，详见日志。' }
        Write-Host "已开始抓包，约 $Seconds 秒后自动停止。" -ForegroundColor Green
        if (-not $NoBrowser) {
            try { Open-CampusPortal } catch {
                Write-Warning '浏览器未能打开，可手动访问 http://neverssl.com。'
            }
        }
        Wait-CampusCapture -Seconds $Seconds
    } catch {
        $captureError = $_
    } finally {
        if ($started) {
            try {
                $stopped = Invoke-CampusPktmon -Arguments @('stop')
                Write-CampusCommandLog $log 'stop' $stopped
                if ($stopped.ExitCode -ne 0) { throw 'pktmon 停止失败，请在管理员终端检查 pktmon status。' }
            } catch { $stopError = $_ }
        }
    }
    if ($stopError) { throw $stopError }
    if ($captureError) { throw $captureError }
    if (-not (Test-Path -LiteralPath $etl -PathType Leaf)) { throw "未生成 ETL，详见 $log" }

    $converted = Invoke-CampusPktmon -Arguments @('etl2pcap', $etl, '--out', $pcap)
    Write-CampusCommandLog $log 'etl2pcap' $converted
    if ($converted.ExitCode -ne 0 -or
        -not (Test-Path -LiteralPath $pcap -PathType Leaf) -or
        (Get-Item -LiteralPath $pcap).Length -le 0) {
        throw "转换失败或输出为空。ETL 已保留：$etl；日志：$log"
    }
    Write-Host '=== 抓包完成 ===' -ForegroundColor Green
    Write-Host "文件: $pcap"
    Write-Host "日志: $log"
    Write-Host '将生成文件的路径发给我即可分析。'
    Write-Host '512 MB 循环日志达到上限会覆盖早期记录；多网卡也可能出现重复包。'
    return $pcap
}

# Dot-sourcing loads functions only, allowing offline lifecycle tests.
if ($MyInvocation.InvocationName -ne '.') {
    $code = 0
    try {
        if (-not (Test-CampusAdministrator)) {
            Write-Host '需要管理员权限，正在请求 UAC...'
            $exe = (Get-Process -Id $PID).Path
            $arguments = New-CampusElevationArguments -ScriptPath $PSCommandPath -Seconds $Seconds `
                -Directory $OutputDirectory -NoBrowser:$NoBrowser -NoPause:$NoPause
            $child = Start-Process -FilePath $exe -ArgumentList $arguments -Verb RunAs -PassThru -Wait -ErrorAction Stop
            exit $child.ExitCode
        }
        Invoke-CampusCapture -Seconds $Seconds -OutputDirectory $OutputDirectory -NoBrowser:$NoBrowser | Out-Null
    } catch {
        Write-Host "抓包未完成: $($_.Exception.Message)" -ForegroundColor Red
        $code = 1
    }
    if (-not $NoPause) { [void](Read-Host '按回车关闭') }
    exit $code
}
