from __future__ import annotations

import platform
from typing import Any

from .common import base_result, mark_error, powershell_json


def collect() -> dict[str, Any]:
    result = base_result("disks")
    if platform.system().lower() != "windows":
        result["status"] = "skipped"
        result["errors"].append("Windows disk collector is only available on Windows.")
        return result

    try:
        script = r"""
        $errors = @()
        $volumes = @()
        $psdrives = @()
        $logicalDisks = @()
        $physicalDisks = @()
        $diskDrives = @()
        $bitlocker = @()

        try {
          if (Get-Command Get-Volume -ErrorAction SilentlyContinue) {
            $volumes = Get-Volume -ErrorAction Stop |
              Select-Object DriveLetter,FileSystemLabel,FileSystem,DriveType,HealthStatus,OperationalStatus,Size,SizeRemaining
          } else {
            $errors += "Get-Volume is not available"
          }
        } catch {
          $errors += "Get-Volume failed: $($_.Exception.Message)"
        }

        try {
          $psdrives = Get-PSDrive -PSProvider FileSystem -ErrorAction Stop |
            Select-Object Name,Root,Used,Free
        } catch {
          $errors += "Get-PSDrive failed: $($_.Exception.Message)"
        }

        try {
          $logicalDisks = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
            Where-Object { $_.DriveType -eq 3 } |
            Select-Object DeviceID,VolumeName,FileSystem,DriveType,Size,FreeSpace
        } catch {
          $errors += "Win32_LogicalDisk failed: $($_.Exception.Message)"
        }

        try {
          if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            $physicalDisks = Get-PhysicalDisk -ErrorAction Stop |
              Select-Object FriendlyName,SerialNumber,MediaType,BusType,Size,HealthStatus,OperationalStatus
          } else {
            $errors += "Get-PhysicalDisk is not available"
          }
        } catch {
          $errors += "Get-PhysicalDisk failed: $($_.Exception.Message)"
        }

        try {
          $diskDrives = Get-CimInstance Win32_DiskDrive -ErrorAction Stop |
            Select-Object Model,SerialNumber,InterfaceType,MediaType,Size,Status
        } catch {
          $errors += "Win32_DiskDrive failed: $($_.Exception.Message)"
        }

        try {
          if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            $bitlocker = Get-BitLockerVolume -ErrorAction Stop |
              Select-Object MountPoint,VolumeStatus,ProtectionStatus,LockStatus,EncryptionPercentage
          } else {
            $errors += "Get-BitLockerVolume is not available"
          }
        } catch {
          $errors += "Get-BitLockerVolume failed: $($_.Exception.Message)"
        }

        $volumeSummary = foreach ($disk in $logicalDisks) {
          $size = [double]($disk.Size)
          $free = [double]($disk.FreeSpace)
          $used = if ($size -gt 0) { $size - $free } else { $null }
          $freePercent = if ($size -gt 0) { [math]::Round(($free / $size) * 100, 2) } else { $null }
          [pscustomobject]@{
            Drive=$disk.DeviceID
            Label=$disk.VolumeName
            FileSystem=$disk.FileSystem
            DriveType=$disk.DriveType
            Size=$size
            Used=$used
            Free=$free
            FreePercent=$freePercent
          }
        }

        [pscustomobject]@{
          Volumes=$volumes
          FileSystemDrives=$psdrives
          LogicalDisks=$logicalDisks
          VolumeSummary=$volumeSummary
          PhysicalDisks=$physicalDisks
          DiskDrives=$diskDrives
          BitLocker=$bitlocker
          Errors=$errors
        } | ConvertTo-Json -Depth 6 -Compress
        """
        data = powershell_json(script, timeout=40)
        result["data"] = data
        if data.get("Errors"):
            errors = data["Errors"] if isinstance(data["Errors"], list) else [data["Errors"]]
            result["errors"].extend(errors)
            if any("Get-BitLockerVolume failed" in str(item) for item in errors):
                result["status"] = "need_admin"
            else:
                result["status"] = "partial"
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        if "not available" in message:
            result["status"] = "skipped"
            result["errors"].append(message)
        elif "Access is denied" in message or "拒绝访问" in message:
            result["status"] = "need_admin"
            result["errors"].append(message)
        else:
            mark_error(result, exc)
    return result
