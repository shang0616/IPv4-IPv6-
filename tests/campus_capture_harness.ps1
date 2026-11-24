param([string]$WorkDirectory)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'campus_capture.ps1')

function Assert-Campus([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

# These replacements make every scenario offline: no UAC, capture, browser,
# sleep, network changes, or real pktmon commands.
function Invoke-CampusPktmon {
    param([string[]]$Arguments)
    $script:Calls.Add(($Arguments -join ' '))
    $code = 0
    switch ($Arguments[0]) {
        'filter' { if ($script:Case -eq 'filter-fails') { $code = 5 } }
        'start' {
            if ($script:Case -eq 'start-fails') { $code = 5 } else {
                $path = $Arguments[([array]::IndexOf($Arguments, '--file-name') + 1)]
                Set-Content -LiteralPath $path -Value 'fake etl' -Encoding ASCII
            }
        }
        'stop' { if ($script:Case -eq 'stop-fails') { $code = 5 } }
        'etl2pcap' {
            $path = $Arguments[([array]::IndexOf($Arguments, '--out') + 1)]
            if ($script:Case -eq 'convert-fails') { $code = 5 }
            if ($script:Case -eq 'convert-empty') {
                [void](New-Item -ItemType File -Path $path)
            } elseif ($script:Case -ne 'convert-missing') {
                Set-Content -LiteralPath $path -Value 'fake pcap' -Encoding ASCII
            }
        }
        default { throw 'Unexpected native operation' }
    }
    return [pscustomobject]@{ ExitCode = $code; Output = 'offline test' }
}
function Wait-CampusCapture {
    param([int]$Seconds)
    Assert-Campus ($Seconds -eq 1) 'duration reaches wait'
    if ($script:Case -eq 'wait-fails') { throw 'simulated interruption' }
}
function Open-CampusPortal {
    if ($script:Case -eq 'browser-fails') { throw 'simulated browser failure' }
}

$cases = @('success', 'browser-fails', 'filter-fails', 'start-fails',
    'wait-fails', 'stop-fails', 'convert-fails', 'convert-empty', 'convert-missing')
foreach ($caseName in $cases) {
    $script:Case = $caseName
    $script:Calls = New-Object 'System.Collections.Generic.List[string]'
    $failed = $false
    try {
        $result = Invoke-CampusCapture -Seconds 1 -OutputDirectory (Join-Path $WorkDirectory $caseName)
    } catch { $failed = $true }
    $expectedFailure = $caseName -notin @('success', 'browser-fails')
    Assert-Campus ($failed -eq $expectedFailure) "$caseName result"
    $stops = @($script:Calls | Where-Object { $_ -eq 'stop' }).Count
    $expectedStops = if ($caseName -in @('filter-fails', 'start-fails')) { 0 } else { 1 }
    Assert-Campus ($stops -eq $expectedStops) "$caseName capture ownership"
    $converts = @($script:Calls | Where-Object { $_ -like 'etl2pcap *' }).Count
    $expectedConverts = if ($caseName -in @('filter-fails', 'start-fails', 'wait-fails', 'stop-fails')) { 0 } else { 1 }
    Assert-Campus ($converts -eq $expectedConverts) "$caseName conversion gate"
    if ($caseName -ne 'filter-fails') {
        $starts = @($script:Calls | Where-Object { $_ -like 'start *' })
        Assert-Campus ($starts.Count -eq 1) "$caseName single start"
        Assert-Campus ($starts[0] -match '--pkt-size 0(?: |$)') 'full packet snap length'
        Assert-Campus ($starts[0] -match '--comp nics --type flow') 'NIC capture only'
    }
    Assert-Campus (@($script:Calls | Where-Object { $_ -like 'filter remove*' }).Count -eq 0) 'preserve global filters'
    if (-not $failed) {
        Assert-Campus ((Get-Item -LiteralPath $result).Length -gt 0) 'success output exists'
    }
}
$script:Case = 'success'
$script:Calls = New-Object 'System.Collections.Generic.List[string]'
$dir = Join-Path $WorkDirectory 'same-directory'
$first = Invoke-CampusCapture -Seconds 1 -OutputDirectory $dir -NoBrowser
$second = Invoke-CampusCapture -Seconds 1 -OutputDirectory $dir -NoBrowser
Assert-Campus ($first -ne $second) 'separate runs use separate files'
Assert-Campus ((Test-Path -LiteralPath $first) -and (Test-Path -LiteralPath $second)) 'both files retained'
Write-Output 'CAMPUS_OFFLINE_TESTS_OK'
