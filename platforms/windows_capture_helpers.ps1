function Convert-PciNetstatLine {
    param([string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    $fields = @($Line.Trim() -split '\s+')
    if ($fields.Count -lt 4) { return $null }
    $protocol = $fields[0].ToUpperInvariant()
    if ($protocol -eq 'TCP') {
        if ($fields.Count -lt 5 -or $fields[3].ToUpperInvariant() -ne 'LISTENING') { return $null }
        if ($fields[4] -notmatch '^\d+$') { return $null }
    }
    elseif ($protocol -eq 'UDP') {
        if ($fields[3] -notmatch '^\d+$') { return $null }
    }
    else { return $null }
    return New-Object PSObject -Property @{
        Protocol = $protocol
        LocalEndpoint = $fields[1]
        ProcessId = [int]$(if ($protocol -eq 'TCP') { $fields[4] } else { $fields[3] })
        State = $(if ($protocol -eq 'TCP') { 'LISTENING' } else { 'BOUND' })
        Line = $Line.Trim()
    }
}

function Select-PciNetstatListeners {
    param([string[]]$Lines, [int]$Limit = 1500)
    $selected = New-Object System.Collections.ArrayList
    $truncated = $false
    foreach ($line in $Lines) {
        $candidate = Convert-PciNetstatLine $line
        if ($null -eq $candidate) { continue }
        if ($selected.Count -ge $Limit) { $truncated = $true; break }
        [void]$selected.Add($candidate)
    }
    return New-Object PSObject -Property @{
        Lines = [object[]]$selected.ToArray()
        Truncated = $truncated
        Count = $selected.Count
    }
}

function Select-PciRows {
    param([object[]]$Rows, [int]$Limit = 1500)
    $selected = New-Object System.Collections.ArrayList
    $truncated = $false
    foreach ($row in $Rows) {
        if ($selected.Count -ge $Limit) { $truncated = $true; break }
        [void]$selected.Add($row)
    }
    return New-Object PSObject -Property @{
        Items = [object[]]$selected.ToArray()
        Truncated = $truncated
        Count = $selected.Count
    }
}

function Convert-PciSecurityPolicyText {
    param([string[]]$Lines)

    $required = @('MinimumPasswordLength', 'PasswordComplexity', 'LockoutBadCount')
    $allowed = @($required + 'MaximumPasswordAge')
    $values = @{}
    $conflicts = New-Object System.Collections.ArrayList
    $section = ''
    foreach ($line in $Lines) {
        if ($line -match '^\s*\[(?<name>[^\]]+)\]\s*$') {
            $section = $matches['name'].Trim()
            continue
        }
        if ($section -ne 'System Access' -or $line -notmatch '^\s*(?<key>[A-Za-z][A-Za-z0-9]+)\s*=\s*(?<value>\S+)\s*$') {
            continue
        }
        $key = $matches['key']
        if ($allowed -notcontains $key) { continue }
        $rawValue = $matches['value']
        if ($rawValue -notmatch '^\d{1,5}$') {
            [void]$conflicts.Add($key + '=INVALID')
            continue
        }
        $parsedValue = [int]$rawValue
        if ($values.ContainsKey($key) -and $values[$key] -ne $parsedValue) {
            [void]$conflicts.Add($key + '=CONFLICT')
            continue
        }
        $values[$key] = $parsedValue
    }

    $missing = @($required | Where-Object { -not $values.ContainsKey($_) })
    $status = 'collected'
    if ($conflicts.Count -gt 0) { $status = 'parse_failed' }
    elseif ($missing.Count -gt 0) { $status = 'missing' }
    return New-Object PSObject -Property @{
        Status = $status
        Values = $values
        MissingFields = [string[]]$missing
        ParseErrors = [string[]]$conflicts.ToArray()
    }
}

function Resolve-PciSecurityPolicyExport {
    param([int]$ExitCode, [bool]$FileExists, [string[]]$Lines)

    if ($ExitCode -ne 0) {
        return New-Object PSObject -Property @{
            Status = 'permission_denied_or_unavailable'
            Values = @{}
            MissingFields = [string[]]@()
            ParseErrors = [string[]]@()
        }
    }
    if (-not $FileExists) {
        return New-Object PSObject -Property @{
            Status = 'missing'
            Values = @{}
            MissingFields = [string[]]@('System Access export')
            ParseErrors = [string[]]@()
        }
    }
    return Convert-PciSecurityPolicyText -Lines $Lines
}

function Assert-PciNoReparsePath {
    param([string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    $parts = $fullPath.Substring($root.Length).Split([char[]]@('\','/'), [System.StringSplitOptions]::RemoveEmptyEntries)
    $current = $root
    foreach ($part in $parts) {
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'REPARSE_PATH_BLOCKED'
            }
        }
    }
    return $fullPath
}

function Remove-PciPrivateTempDirectory {
    param([string]$Path, [string]$Prefix)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([char[]]@('\','/'))
    $volumeRoot = [System.IO.Path]::GetPathRoot($tempRoot)
    if ([string]::Equals($tempRoot, $volumeRoot.TrimEnd([char[]]@('\','/')), [System.StringComparison]::OrdinalIgnoreCase)) {
        $tempRoot = $volumeRoot
    }
    $target = [System.IO.Path]::GetFullPath($Path)
    $parent = [System.IO.Directory]::GetParent($target)
    if ($null -eq $parent -or -not [string]::Equals($parent.FullName.TrimEnd([char[]]@('\','/')), $tempRoot.TrimEnd([char[]]@('\','/')), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'TEMP_CLEANUP_TARGET_OUTSIDE_TEMP_ROOT'
    }
    $expectedName = '^' + [regex]::Escape($Prefix) + '-[a-fA-F0-9]{32}$'
    if ([System.IO.Path]::GetFileName($target) -notmatch $expectedName) {
        throw 'TEMP_CLEANUP_TARGET_NAME_INVALID'
    }
    if (-not (Test-Path -LiteralPath $target -PathType Container)) { return }
    [void](Assert-PciNoReparsePath -Path $target)
    $directory = Get-Item -LiteralPath $target -Force -ErrorAction Stop
    if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'TEMP_CLEANUP_TARGET_REPARSE_BLOCKED'
    }
    foreach ($child in @(Get-ChildItem -LiteralPath $target -Force -ErrorAction Stop)) {
        if ($child.PSIsContainer -or (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'TEMP_CLEANUP_CHILD_TYPE_BLOCKED'
        }
        Remove-Item -LiteralPath $child.FullName -Force -ErrorAction Stop
    }
    Remove-Item -LiteralPath $target -Force -ErrorAction Stop
}

function Get-PciHotfixSummary {
    param([object[]]$Hotfixes)

    $all = @($Hotfixes)
    $parsedDates = New-Object System.Collections.ArrayList
    $unresolved = $false
    foreach ($hotfix in $all) {
        $raw = $null
        if ($null -ne $hotfix) { $raw = $hotfix.InstalledOn }
        if ($null -eq $raw -or [string]::IsNullOrWhiteSpace([string]$raw)) {
            $unresolved = $true
            continue
        }
        if ($raw -is [datetime]) {
            [void]$parsedDates.Add($raw.Date)
            continue
        }

        $value = ([string]$raw).Trim()
        $parsed = [datetime]::MinValue
        $dateFormats = @('yyyy-MM-dd', 'yyyy-M-d', 'yyyyMMdd', 'yyyy-MM-ddTHH:mm:ss', 'yyyy-MM-dd HH:mm:ss')
        $dateOk = [datetime]::TryParseExact($value, $dateFormats, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
        if (-not $dateOk -and $value -match '^(?<first>\d{1,2})/(?<second>\d{1,2})/(?<year>\d{4})$') {
            $first = [int]$matches['first']
            $second = [int]$matches['second']
            if ($first -gt 12 -and $second -le 12) {
                $dateOk = [datetime]::TryParseExact($value, @('d/M/yyyy', 'dd/MM/yyyy'),
                    [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
            }
            elseif ($second -gt 12 -and $first -le 12) {
                $dateOk = [datetime]::TryParseExact($value, @('M/d/yyyy', 'MM/dd/yyyy'),
                    [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
            }
            elseif ($first -eq $second -and $first -ge 1 -and $first -le 12) {
                $dateOk = [datetime]::TryParseExact($value, @('M/d/yyyy', 'MM/dd/yyyy'),
                    [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
            }
        }
        if ($dateOk) { [void]$parsedDates.Add($parsed.Date) }
        else { $unresolved = $true }
    }

    $status = 'collected'
    $latest = $null
    if ($unresolved -or $parsedDates.Count -eq 0) {
        $status = 'unknown'
    }
    else {
        $latestDate = @($parsedDates.ToArray() | Sort-Object)[-1]
        $latest = $latestDate.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return New-Object PSObject -Property @{
        Status = $status
        Count = $all.Count
        LatestInstalled = $latest
    }
}
