param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$script:CollectorVersion = '0.3.0-landable'
$script:CommandCatalog = 'collection_time,os,os_detail,os_architecture,cpu,memory,graphics,disks,processes,services,listeners,firewall,privilege,accounts,startup_items,security_status'
$script:EvidenceNames = @(
    'collection_start.txt', 'collection_finish.txt', 'collection_metadata.txt',
    'os.txt', 'os_detail.txt', 'os_architecture.txt', 'cpu.txt', 'memory.txt',
    'graphics.txt', 'disks.txt', 'processes.txt', 'services.txt', 'listeners.txt',
    'firewall.txt', 'privilege.txt', 'accounts.txt', 'startup_items.txt',
    'security_status.txt'
)
$script:MaxEvidenceBytes = 2097152
$script:MaxRows = 1500
$script:HelperPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'windows_capture_helpers.ps1'
. $script:HelperPath

function Write-Utf8File {
    param([string]$Path, [string[]]$Lines)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($Path, $false, $encoding)
    try {
        foreach ($line in $Lines) { $writer.WriteLine($line) }
    }
    finally { $writer.Dispose() }
}

function Write-Sidecar {
    param([string]$Name, [int]$ExitCode, [string]$Status)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($Name)
    $path = Join-Path $OutputDirectory ($base + '.exit-code.txt')
    $sidecarLines = [string[]]@(
        ('EXIT_CODE=' + $ExitCode),
        ('STATUS=' + $Status)
    )
    [System.IO.File]::WriteAllLines($path, $sidecarLines, [System.Text.Encoding]::ASCII)
}

function Get-PrivilegeLabel {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { return 'administrator' }
        return 'ordinary'
    }
    catch { return 'unknown' }
}

function Invoke-FixedCollector {
    param([string]$Name, [string]$PolicyTempDirectory)

    $worker = {
        param($CollectorName, $PolicyTempDirectory, $HelperPath, [int]$MaxRows)
        $ErrorActionPreference = 'Stop'
        . $HelperPath
        $script:MaxRows = $MaxRows
        $lines = New-Object System.Collections.ArrayList
        $state = 'OK'
        function Add-Line([string]$Value) {
            if ($null -eq $Value) { return }
            $safe = [string]$Value -replace '[\r\n\t\x00]', ' '
            if ($safe.Length -gt 2048) { $safe = $safe.Substring(0, 2048) }
            if ($lines.Count -lt 2000) { [void]$lines.Add($safe) }
            else { $script:RowLimitHit = $true }
        }
        function Add-Field([string]$Key, $Value) {
            if ($null -ne $Value) { Add-Line ($Key + '=' + [string]$Value) }
        }
        function Add-ObservedField([string]$Key, $Value) {
            if ($null -eq $Value) {
                Add-Line ($Key + '=UNKNOWN')
                $script:UnknownFactHit = $true
            }
            else { Add-Field $Key $Value }
        }
        function Mark-Truncated([string]$Reason) {
            $script:RowLimitHit = $true
            if ($lines.Count -lt 2000) { Add-Line ('TRUNCATED=' + $Reason) }
        }
        function Get-RegValue([string]$Path, [string]$Name) {
            try {
                $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
                return $item.$Name
            }
            catch { return $null }
        }
        function Get-RegistryFacts([string]$Path, [string[]]$Names) {
            $result = @{}
            foreach ($name in $Names) { $result[$name] = Get-RegValue $Path $name }
            return $result
        }
        function Get-ServiceExecutablePath([string]$CommandLine) {
            $match = [regex]::Match($CommandLine, '^\s*"(?<path>[^"]+?\.exe)"|^\s*(?<path>[^"\s]+?\.exe)(?:\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $match.Success) { return 'UNKNOWN' }
            return [regex]::Replace($match.Groups['path'].Value, '(?i)\\Users\\[^\\]+', '\Users\<redacted>')
        }
        function Get-StartupCommandFacts([string]$CommandLine) {
            $imagePattern = '(?i)^\s*"(?<quoted>(?:[A-Z]:\\|\\\\)[^"]+?\.exe)"|^\s*(?<bare>(?:(?:[A-Z]:\\|\\\\)[^\s"]+?\.exe|[^\s"]+?\.exe))(?=\s|$)'
            $imageMatch = [regex]::Match($CommandLine, $imagePattern)
            $imagePath = $imageMatch.Groups['quoted'].Value
            if (-not $imagePath) { $imagePath = $imageMatch.Groups['bare'].Value }
            if (-not $imagePath) { $imagePath = 'UNKNOWN' }

            $scriptExtensions = '(?:ps1|bat|cmd|vbs|js|jse|wsf|hta)'
            $scriptPattern = '(?i)(?:^|\s)(?:-File|-f|/c|/k)\s+"(?<quoted>(?:[A-Z]:\\|\\\\)[^"]+\.' + $scriptExtensions + ')"|(?:^|\s)(?:-File|-f|/c|/k)\s+(?<bare>(?:[A-Z]:\\|\\\\)[^\s"]+\.' + $scriptExtensions + ')(?=\s|$)'
            $scriptMatch = [regex]::Match($CommandLine, $scriptPattern)
            if (-not $scriptMatch.Success) {
                $scriptPattern = '(?i)^\s*"(?<quoted>(?:[A-Z]:\\|\\\\)[^"]+\.' + $scriptExtensions + ')"|^\s*(?<bare>(?:[A-Z]:\\|\\\\)[^\s"]+\.' + $scriptExtensions + ')(?=\s|$)'
                $scriptMatch = [regex]::Match($CommandLine, $scriptPattern)
            }
            $scriptPath = ''
            $wrappedUnresolvedCommand = $imagePath -eq 'UNKNOWN' -and
                $CommandLine -match '(?i)^\s*"[^"]+\.(?:exe|com|sys|dll|cmd|bat|vbs|js|jse|wsf|hta|ps1)\s+'
            if (-not $wrappedUnresolvedCommand) {
                $scriptPath = $scriptMatch.Groups['quoted'].Value
                if (-not $scriptPath) { $scriptPath = $scriptMatch.Groups['bare'].Value }
            }
            if ($scriptPath -and $scriptPath -match ('(?i)\.(?:exe|com|sys|dll|cmd|bat|vbs|js|jse|wsf|hta|ps1)\s+')) {
                $scriptPath = ''
            }
            $scriptExtension = 'UNKNOWN'
            if ($scriptPath) {
                $extensionMatch = [regex]::Match($scriptPath, '(?i)\.(ps1|bat|cmd|vbs|js|jse|wsf|hta)$')
                if ($extensionMatch.Success) { $scriptExtension = '.' + $extensionMatch.Groups[1].Value.ToLowerInvariant() }
            }
            return [pscustomobject]@{
                ImagePath = [regex]::Replace($imagePath, '(?i)\\Users\\[^\\]+', '\Users\<redacted>')
                ScriptPath = [regex]::Replace($(if ($scriptPath) { $scriptPath } else { 'UNKNOWN' }), '(?i)\\Users\\[^\\]+', '\Users\<redacted>')
                ScriptExtension = $scriptExtension
            }
        }
        $script:RowLimitHit = $false
        $script:UnknownFactHit = $false

        try {
            switch ($CollectorName) {
                'os' {
                    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                    $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
                    Add-Field 'Hostname' $env:COMPUTERNAME
                    Add-Field 'Caption' $os.Caption
                    Add-Field 'Version' $os.Version
                    Add-Field 'BuildNumber' $os.BuildNumber
                    Add-Field 'OSArchitecture' $os.OSArchitecture
                    Add-Field 'LastBootUpTime' $os.ConvertToDateTime($os.LastBootUpTime).ToString('o')
                    Add-Field 'Manufacturer' $cs.Manufacturer
                    Add-Field 'Model' $cs.Model
                    Add-Field 'TotalPhysicalMemory' $cs.TotalPhysicalMemory
                }
                'os_detail' {
                    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                    Add-Field 'Caption' $os.Caption
                    Add-Field 'Version' $os.Version
                    Add-Field 'BuildNumber' $os.BuildNumber
                    Add-Field 'OSArchitecture' $os.OSArchitecture
                    Add-Field 'ProductType' $os.ProductType
                }
                'os_architecture' {
                    Add-Field 'PROCESSOR_ARCHITECTURE' $env:PROCESSOR_ARCHITECTURE
                    Add-Field 'PROCESSOR_ARCHITEW6432' $env:PROCESSOR_ARCHITEW6432
                }
                'cpu' {
                    $count = 0
                    foreach ($cpu in @(Get-WmiObject -Class Win32_Processor -ErrorAction Stop)) {
                        if ($count -ge 64) { Mark-Truncated 'cpu:more_than_64'; break }
                        Add-Line ('Name=' + $cpu.Name)
                        Add-Line ('NumberOfCores=' + $cpu.NumberOfCores)
                        Add-Line ('NumberOfLogicalProcessors=' + $cpu.NumberOfLogicalProcessors)
                        Add-Line ('LoadPercentage=' + $cpu.LoadPercentage)
                        Add-Line '---'
                        $count++
                    }
                }
                'memory' {
                    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                    $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
                    Add-Field 'TotalPhysicalMemory' $cs.TotalPhysicalMemory
                    Add-Field 'FreePhysicalMemory_kB' $os.FreePhysicalMemory
                    Add-Field 'TotalVisibleMemorySize_kB' $os.TotalVisibleMemorySize
                }
                'graphics' {
                    $count = 0
                    foreach ($card in @(Get-WmiObject -Class Win32_VideoController -ErrorAction Stop)) {
                        if ($count -ge 32) { Mark-Truncated 'graphics:more_than_32'; break }
                        Add-Field 'Name' $card.Name
                        Add-Field 'AdapterRAM' $card.AdapterRAM
                        Add-Line '---'
                        $count++
                    }
                }
                'disks' {
                    $allVolumes = @(Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
                    $volumeSelection = Select-PciRows -Rows $allVolumes -Limit 128
                    if ($volumeSelection.Truncated) { Mark-Truncated 'disks:more_than_128' }
                    $volumes = $volumeSelection.Items
                    foreach ($volume in $volumes) {
                        $percent = $null
                        if ([double]$volume.Size -gt 0) { $percent = [math]::Round(([double]$volume.FreeSpace / [double]$volume.Size) * 100, 2) }
                        Add-Line ('Drive=' + $volume.DeviceID + ';FileSystem=' + $volume.FileSystem + ';SizeBytes=' + $volume.Size + ';FreeBytes=' + $volume.FreeSpace + ';FreePercent=' + $percent)
                    }
                    Add-Field 'RecordCount' $volumeSelection.Count
                }
                'processes' {
                    $allProcesses = @(Get-WmiObject -Class Win32_Process -ErrorAction Stop)
                    $processSelection = Select-PciRows -Rows $allProcesses -Limit $script:MaxRows
                    if ($processSelection.Truncated) { Mark-Truncated 'processes:more_than_1500' }
                    foreach ($item in $processSelection.Items) {
                        Add-Line ('Name=' + $item.Name + ';ProcessId=' + $item.ProcessId + ';ParentProcessId=' + $item.ParentProcessId + ';WorkingSetBytes=' + $item.WorkingSetSize + ';ThreadCount=' + $item.ThreadCount)
                    }
                    Add-Field 'RecordCount' $processSelection.Count
                    Add-Line 'CommandLineAndExecutablePath=OMITTED_FOR_PRIVACY'
                }
                'services' {
                    $allServices = @(Get-WmiObject -Class Win32_Service -ErrorAction Stop)
                    $serviceSelection = Select-PciRows -Rows $allServices -Limit $script:MaxRows
                    if ($serviceSelection.Truncated) { Mark-Truncated 'services:more_than_1500' }
                    foreach ($item in $serviceSelection.Items) {
                        $imagePath = Get-ServiceExecutablePath ([string]$item.PathName)
                        if ($imagePath -eq 'UNKNOWN') { $script:UnknownFactHit = $true }
                        Add-Line ('Name=' + $item.Name + ';State=' + $item.State + ';StartMode=' + $item.StartMode + ';ProcessId=' + $item.ProcessId + ';PathName=' + $imagePath)
                    }
                    Add-Field 'RecordCount' $serviceSelection.Count
                }
                'listeners' {
                    $netstat = Join-Path $env:SystemRoot 'System32\netstat.exe'
                    if (-not (Test-Path -LiteralPath $netstat -PathType Leaf)) { throw 'TOOL_UNAVAILABLE:netstat.exe' }
                    $info = New-Object System.Diagnostics.ProcessStartInfo
                    $info.FileName = $netstat
                    $info.Arguments = '-ano'
                    $info.UseShellExecute = $false
                    $info.CreateNoWindow = $true
                    $info.RedirectStandardOutput = $true
                    $proc = New-Object System.Diagnostics.Process
                    $proc.StartInfo = $info
                    [void]$proc.Start()
                    $listenerCount = 0
                    while ($true) {
                        $line = $proc.StandardOutput.ReadLine()
                        if ($null -eq $line) { break }
                        $listener = Convert-PciNetstatLine $line
                        if ($null -eq $listener) { continue }
                        if ($listenerCount -ge $script:MaxRows) {
                            Mark-Truncated 'listeners:more_than_1500_tcp_or_udp_bindings'
                            $proc.Kill()
                            [void]$proc.WaitForExit(5000)
                            break
                        }
                        Add-Line $listener.Line
                        $listenerCount++
                    }
                    if (-not $proc.HasExited) { [void]$proc.WaitForExit(5000) }
                    if (-not $proc.HasExited) { $proc.Kill(); throw 'COMMAND_FAILED:netstat_cleanup' }
                    if ($proc.ExitCode -ne 0 -and -not $script:RowLimitHit) { throw ('COMMAND_FAILED:netstat:' + $proc.ExitCode) }
                    $proc.Dispose()
                }
                'firewall' {
                    $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
                    if (-not (Test-Path -LiteralPath $netsh -PathType Leaf)) { throw 'TOOL_UNAVAILABLE:netsh.exe' }
                    $output = @(& $netsh advfirewall show allprofiles 2>$null)
                    $code = $LASTEXITCODE
                    if ($code -ne 0) { throw ('COMMAND_FAILED:netsh:' + $code) }
                    if ($output.Count -gt 256) { Mark-Truncated 'firewall:more_than_256_lines' }
                    foreach ($line in ($output | Select-Object -First 256)) { Add-Line $line }
                }
                'privilege' {
                    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
                    $admin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
                    Add-Field 'Privilege' $(if ($admin) { 'administrator' } else { 'ordinary' })
                    Add-Field 'Integrity' $(if ($admin) { 'administrator-capable-token' } else { 'standard-user-token' })
                }
                'accounts' {
                    $items = @(Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
                    $enabled = @($items | Where-Object { -not $_.Disabled })
                    $guest = @($items | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1)
                    Add-Field 'LocalAccountCount' $items.Count
                    Add-Field 'EnabledLocalAccountCount' $enabled.Count
                    if ($guest.Count -gt 0) { Add-Field 'GuestEnabled' ([bool](-not $guest[0].Disabled)) }
                    else { Add-Line 'GuestEnabled=UNKNOWN' }
                    try {
                        $adminGroups = @(Get-WmiObject -Class Win32_Group -Filter "SID='S-1-5-32-544'" -ErrorAction Stop)
                        if ($adminGroups.Count -ne 1) { throw 'LOCAL_ADMINISTRATORS_GROUP_UNKNOWN' }
                        $memberQuery = 'ASSOCIATORS OF {' + $adminGroups[0].__RELPATH + '} WHERE AssocClass=Win32_GroupUser Role=GroupComponent'
                        $adminMembers = @(Get-WmiObject -Query $memberQuery -ErrorAction Stop)
                        Add-Field 'AdministratorMemberCount' $adminMembers.Count
                    }
                    catch { Add-Line 'AdministratorMemberCount=UNKNOWN'; $state = 'PARTIAL' }
                    Add-Line 'AccountNamesAndSIDs=OMITTED_FOR_PRIVACY'
                }
                'startup_items' {
                    $count = 0
                    foreach ($item in @(Get-WmiObject -Class Win32_StartupCommand -ErrorAction Stop)) {
                        if ($count -ge 500) { Mark-Truncated 'startup_items:more_than_500'; break }
                        $command = [string]$item.Command
                        $commandFacts = Get-StartupCommandFacts $command
                        $imagePath = $commandFacts.ImagePath
                        $scriptPath = $commandFacts.ScriptPath
                        $scriptExtension = $commandFacts.ScriptExtension
                        if ($imagePath -eq 'UNKNOWN') { $script:UnknownFactHit = $true }
                        $safeName = [regex]::Replace([string]$item.Name, '[;\r\n\t\x00]', ' ')
                        $safeLocation = [regex]::Replace([string]$item.Location, '[;\r\n\t\x00]', ' ')
                        $safeImagePath = [regex]::Replace($imagePath, '(?i)\\Users\\[^\\]+', '\Users\<redacted>')
                        $safeScriptPath = [regex]::Replace($scriptPath, '(?i)\\Users\\[^\\]+', '\Users\<redacted>')
                        $safeLocation = [regex]::Replace($safeLocation, '(?i)\\Users\\[^\\]+', '\Users\<redacted>')
                        $scope = if ($safeLocation -match '(?i)HKCU|Current User') { 'CurrentUser' } else { 'MachineOrUnknown' }
                        Add-Line ('Name=' + $safeName + ';Location=' + $safeLocation + ';ImagePath=' + $safeImagePath + ';ScriptPath=' + $safeScriptPath + ';ScriptExtension=' + $scriptExtension + ';Scope=' + $scope + ';SourceType=Win32_StartupCommand')
                        $count++
                    }
                    Add-Field 'RecordCount' $count
                    Add-Line 'ArgumentsAndUserNames=OMITTED_FOR_PRIVACY'
                }
                'security_status' {
                    $base = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server'
                    $rdp = Get-RegistryFacts $base @('fDenyTSConnections')
                    $rdpNla = Get-RegistryFacts ($base + '\WinStations\RDP-Tcp') @('UserAuthentication')
                    $smb = Get-RegistryFacts 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' @('SMB1')
                    $winlogon = Get-RegistryFacts 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' @('AutoAdminLogon')
                    Add-ObservedField 'RdpDisabled' $rdp['fDenyTSConnections']
                    Add-ObservedField 'RdpNlaRequired' $rdpNla['UserAuthentication']
                    Add-ObservedField 'Smb1ExplicitValue' $smb['SMB1']
                    Add-ObservedField 'AutoAdminLogonEnabled' $winlogon['AutoAdminLogon']
                    foreach ($profile in @('DomainProfile','StandardProfile','PublicProfile')) {
                        $values = Get-RegistryFacts ('Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' + $profile) @('EnableFirewall','DefaultInboundAction')
                        if ($null -eq $values['EnableFirewall']) { $values['EnableFirewall'] = 'UNKNOWN'; $script:UnknownFactHit = $true }
                        if ($null -eq $values['DefaultInboundAction']) { $values['DefaultInboundAction'] = 'UNKNOWN'; $script:UnknownFactHit = $true }
                        Add-Line ('FirewallProfile=' + $profile + ';Enabled=' + $values['EnableFirewall'] + ';DefaultInboundAction=' + $values['DefaultInboundAction'])
                    }
                    try {
                        $localAccounts = @(Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
                        $guest = @($localAccounts | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1)
                        if ($guest.Count -gt 0) { Add-ObservedField 'GuestEnabled' ([bool](-not $guest[0].Disabled)) }
                        else { Add-ObservedField 'GuestEnabled' $null }
                    }
                    catch { Add-Line 'COLLECTOR_NOTE=Local account summary requires additional permission or WMI support'; $state = 'PARTIAL' }
                    try {
                        $policy = Join-Path $PolicyTempDirectory 'merged-security-policy.inf'
                        $log = Join-Path $PolicyTempDirectory 'secedit.log'
                        $secedit = Join-Path $env:SystemRoot 'System32\secedit.exe'
                        if (-not (Test-Path -LiteralPath $secedit -PathType Leaf)) { Add-Line 'PasswordPolicy=TOOL_UNAVAILABLE' ; $state = 'PARTIAL' }
                        else {
                            & $secedit /export /mergedpolicy /cfg $policy /areas securitypolicy /log $log /quiet 2>$null | Out-Null
                            $code = $LASTEXITCODE
                            $policyExists = Test-Path -LiteralPath $policy -PathType Leaf
                            $policyLines = @()
                            if ($policyExists) { $policyLines = @(Get-Content -LiteralPath $policy -ErrorAction Stop) }
                            $parsedPolicy = Resolve-PciSecurityPolicyExport -ExitCode $code -FileExists $policyExists -Lines $policyLines
                            Add-Field 'PasswordPolicyStatus' $parsedPolicy.Status
                            foreach ($entry in $parsedPolicy.Values.GetEnumerator()) {
                                Add-Field $entry.Key $entry.Value
                            }
                            if ($parsedPolicy.Status -ne 'collected') {
                                if ($parsedPolicy.MissingFields.Count -gt 0) {
                                    Add-Field 'PasswordPolicyMissingFields' ($parsedPolicy.MissingFields -join ',')
                                }
                                if ($parsedPolicy.ParseErrors.Count -gt 0) {
                                    Add-Field 'PasswordPolicyParseErrors' ($parsedPolicy.ParseErrors -join ',')
                                }
                                Add-Line 'COLLECTOR_NOTE=Effective password/account policy export lacked complete parseable System Access fields'
                                $state = 'PARTIAL'
                            }
                        }
                    }
                    catch { Add-Line 'PasswordPolicy=PERMISSION_DENIED_OR_UNAVAILABLE'; $state = 'PARTIAL' }
                    $auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'
                    if (Test-Path -LiteralPath $auditpol -PathType Leaf) {
                        try {
                            $auditOutput = @(& $auditpol /get /category:* /r 2>$null)
                            if ($LASTEXITCODE -eq 0) {
                                $auditRecords = @($auditOutput | ConvertFrom-Csv)
                                if ($auditRecords.Count -gt 256) { Mark-Truncated 'audit_policy:more_than_256_rows' }
                                foreach ($record in ($auditRecords | Select-Object -First 256)) {
                                    $values = @($record.PSObject.Properties | ForEach-Object { $_.Value })
                                    if ($values.Count -ge 6) { Add-Line ('AuditSubcategory=' + $values[2] + ';Guid=' + $values[3] + ';Inclusion=' + $values[4] + ';Exclusion=' + $values[5]) }
                                }
                                Add-Field 'AuditPolicyEntryCount' $auditRecords.Count
                            }
                            else { Add-Line 'AuditPolicy=PERMISSION_DENIED_OR_UNAVAILABLE'; $state = 'PARTIAL' }
                        }
                        catch { Add-Line 'AuditPolicy=PERMISSION_DENIED_OR_UNAVAILABLE'; $state = 'PARTIAL' }
                    }
                    else { Add-Line 'AuditPolicy=TOOL_UNAVAILABLE'; $state = 'PARTIAL' }
                    try {
                        $qfe = @(Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction Stop)
                        if ($qfe.Count -gt 1000) { Mark-Truncated 'hotfixes:more_than_1000' }
                        $qfe = @($qfe | Select-Object -First 1000)
                        Add-Field 'HotfixCount' $qfe.Count
                        $patchSummary = Get-PciHotfixSummary -Hotfixes $qfe
                        if ($patchSummary.Status -eq 'collected') { Add-Field 'LatestHotfixDate' $patchSummary.LatestInstalled }
                        else { Add-Line 'LatestHotfixDate=UNKNOWN'; Add-Line 'PatchDateStatus=UNKNOWN'; $state = 'PARTIAL' }
                        Add-Line 'PatchFreshness=NOT_RATED_WITHOUT_APPROVED_POLICY'
                    }
                    catch { Add-Line 'HotfixSummary=UNAVAILABLE'; $state = 'PARTIAL' }
                }
                default { throw ('UNKNOWN_COLLECTOR:' + $CollectorName) }
            }
        }
        catch {
            $message = [string]$_.Exception.Message
            if ($message -match 'Access is denied|\u62d2\u7edd\u8bbf\u95ee|Permission denied') { $state = 'NEED_ADMIN' }
            elseif ($message -match '^TOOL_UNAVAILABLE:') { $state = 'TOOL_UNAVAILABLE' }
            else { $state = 'FAILED' }
            [void]$lines.Clear()
            Add-Line ('COLLECTOR_ERROR=' + $message)
        }
        if (($script:RowLimitHit -or $script:UnknownFactHit) -and $state -eq 'OK') { $state = 'PARTIAL' }
        return (New-Object PSObject -Property @{ Status = $state; Lines = [string[]]$lines.ToArray() })
    }

    $timeout = 25
    if (@('processes','services','accounts','startup_items','security_status') -contains $Name) { $timeout = 35 }
    $job = $null
    try {
        $job = Start-Job -ScriptBlock $worker -ArgumentList @($Name, $PolicyTempDirectory, $script:HelperPath, $script:MaxRows) -ErrorAction Stop
        $completed = Wait-Job -Job $job -Timeout $timeout
        if ($null -eq $completed) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            return @{ Status = 'TIMEOUT'; Lines = @('COLLECTOR_ERROR=Timed out after ' + $timeout + ' seconds') }
        }
        $result = Receive-Job -Job $job -ErrorAction Stop | Select-Object -Last 1
        if ($null -eq $result -or -not $result.PSObject.Properties['Status']) {
            return @{ Status = 'FAILED'; Lines = @('COLLECTOR_ERROR=Collector returned no structured result') }
        }
        return @{ Status = [string]$result.Status; Lines = @($result.Lines) }
    }
    catch {
        return @{ Status = 'TOOL_UNAVAILABLE'; Lines = @('COLLECTOR_ERROR=PowerShell background jobs are unavailable') }
    }
    finally {
        if ($null -ne $job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
    }
}

function Write-CollectorEvidence {
    param([string]$Name, [hashtable]$Result)
    $status = [string]$Result.Status
    $lines = @($Result.Lines)
    $exitCode = 0
    $sidecarStatus = 'COLLECTED'
    switch ($status) {
        'OK' { }
        'PARTIAL' { $lines = @('COLLECTOR_STATUS=PARTIAL') + $lines }
        'NEED_ADMIN' { $lines = @('COLLECTOR_STATUS=NEED_ADMIN') + $lines }
        'TOOL_UNAVAILABLE' { $lines = @('COLLECTOR_STATUS=TOOL_UNAVAILABLE') + $lines }
        default { $exitCode = 4; $sidecarStatus = $status.ToUpperInvariant(); $lines = @('COLLECTOR_STATUS=FAILED') + $lines }
    }
    $path = Join-Path $OutputDirectory ($Name + '.txt')
    $encoded = [System.Text.Encoding]::UTF8.GetBytes(($lines -join "`r`n") + "`r`n")
    if ($encoded.Length -gt $script:MaxEvidenceBytes) {
        $lines = @('COLLECTOR_STATUS=PARTIAL', 'COLLECTOR_ERROR=OUTPUT_LIMIT_EXCEEDED')
        $status = 'PARTIAL'
    }
    Write-Utf8File $path $lines
    Write-Sidecar ($Name + '.txt') $exitCode $sidecarStatus
    if ($status -ne 'OK') { return $true }
    return $false
}

try {
    $OutputDirectory = Assert-PciNoReparsePath -Path $OutputDirectory
    if (Test-Path -LiteralPath $OutputDirectory) {
        $existingOutput = Get-Item -LiteralPath $OutputDirectory -Force -ErrorAction Stop
        if (-not $existingOutput.PSIsContainer) { throw 'OUTPUT_PATH_EXISTS_NOT_DIRECTORY' }
    }
    else {
        New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
    }
    $OutputDirectory = Assert-PciNoReparsePath -Path $OutputDirectory
    if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction Stop).Count -gt 0) {
        throw 'Refusing to reuse a non-empty output directory.'
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}

$tempRoot = [System.IO.Path]::GetTempPath()
[void](Assert-PciNoReparsePath -Path $tempRoot)
$policyTempDirectory = Join-Path $tempRoot ('pc-inspection-toolkit-' + [guid]::NewGuid().ToString('N'))
$partial = $false
$startedAt = [DateTimeOffset]::UtcNow.ToString('o')
Write-Utf8File (Join-Path $OutputDirectory 'collection_start.txt') @($startedAt)
Write-Sidecar 'collection_start.txt' 0 'COLLECTED'

try {
    if (Test-Path -LiteralPath $policyTempDirectory) { throw 'TEMP_DIRECTORY_COLLISION' }
    New-Item -ItemType Directory -Path $policyTempDirectory -ErrorAction Stop | Out-Null
    [void](Assert-PciNoReparsePath -Path $policyTempDirectory)
    $catalogNames = @('os','os_detail','os_architecture','cpu','memory','graphics','disks','processes','services','listeners','firewall','privilege','accounts','startup_items','security_status')
    foreach ($name in $catalogNames) {
        $result = Invoke-FixedCollector $name $policyTempDirectory
        if (Write-CollectorEvidence $name $result) { $partial = $true }
    }
    $finishedAt = [DateTimeOffset]::UtcNow.ToString('o')
    Write-Utf8File (Join-Path $OutputDirectory 'collection_finish.txt') @($finishedAt)
    Write-Sidecar 'collection_finish.txt' 0 'COLLECTED'
    $privilegeResult = Get-Content -LiteralPath (Join-Path $OutputDirectory 'privilege.txt') -ErrorAction SilentlyContinue | Select-String '^Privilege=(ordinary|administrator)$' | Select-Object -First 1
    $privilege = 'unknown'
    if ($null -ne $privilegeResult) { $privilege = ($privilegeResult.Line -split '=', 2)[1] }
    $metadata = [string[]]@(
        'metadata_schema=1',
        ('started_at=' + $startedAt),
        ('finished_at=' + $finishedAt),
        'timezone=UTC',
        ('privilege=' + $privilege),
        ('collector_version=' + $script:CollectorVersion),
        ('command_catalog=' + $script:CommandCatalog)
    )
    Write-Utf8File (Join-Path $OutputDirectory 'collection_metadata.txt') $metadata
    Write-Sidecar 'collection_metadata.txt' 0 'COLLECTED'
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $partial = $true
}
finally {
    try { Remove-PciPrivateTempDirectory -Path $policyTempDirectory -Prefix 'pc-inspection-toolkit' }
    catch { [Console]::Error.WriteLine('Private policy temporary data cleanup failed.'); $partial = $true }
}

if ($partial) {
    Write-Output 'Capture PARTIAL. Inspect each evidence file and sidecar; inaccessible checks remain gaps.'
    exit 4
}
Write-Output 'Capture COMPLETE for the fixed PowerShell command catalog.'
exit 0
