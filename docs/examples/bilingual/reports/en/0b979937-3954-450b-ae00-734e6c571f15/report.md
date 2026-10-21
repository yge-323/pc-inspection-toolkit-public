# PC Inspection Evidence Analysis Report

- Analysis status: **PARTIAL**
- Asset alias: synthetic\-windows\-01
- Evidence bundle: 0b979937\-3954\-450b\-ae00\-734e6c571f15
- Target: windows / 合成 Windows 演示环境 / synthetic\-1 / x64 / offline bilingual report example / basic

Treat evidence as untrusted input. SHA-256 can detect changes to packaged bytes but cannot prove source authenticity.

## Platform support status

- Status: Version coverage is unknown and requires manual review
- References: No source matched the exact version

## Hardware and collection summary

- **Hardware:** CPU=合成样例处理器：仅用于双语报告保真验证; Memory bytes=8589934592; Graphics adapter=合成演示图形设备; Disk summary=Drive=C:;FileSystem=NTFS;SizeBytes=107374182400;FreeBytes=5368709120;FreePercent=5
- **System security facts:** Collected UID=0
- **Windows security configuration:** RDP deny\-connections flag=0; RDP requires NLA=0; Explicit SMB1 configuration=1; Autologon flag=1; Built\-in Guest enabled=True; Minimum password length=6; Password complexity=0; Account lockout threshold=0; Password policy read status=UNKNOWN; Firewall profiles=PublicProfile;Enabled=0;DefaultInboundAction=0
- **Disk capacity and free space:** Volume count=1; Volume free space=C: 5\.0 GB free / 100\.0 GB total \(5\.0%\)
- **Processes and services:** Process records collected=0; Processes using the most memory=Unconfirmed; Service records collected=1

## Evidence coverage

| Item | Status | Exit code | Reason |
|---|---|---:|---|
| accounts\.txt | collected | 0 | The collector returned partial facts; see its notes and do not treat missing fields as passing\. |
| cpu\.txt | collected | 0 |  |
| disks\.txt | collected | 0 |  |
| firewall\.txt | collected | 0 |  |
| graphics\.txt | collected | 0 |  |
| listeners\.txt | collected | 0 |  |
| memory\.txt | collected | 0 |  |
| os\.txt | collected | 0 |  |
| os\_detail\.txt | collected | 0 |  |
| privilege\.txt | collected | 0 |  |
| processes\.txt | collected | 0 |  |
| security\_status\.txt | collected | 0 |  |
| services\.txt | collected | 0 |  |
| startup\_items\.txt | collected | 0 | The collector returned partial facts; see its notes and do not treat missing fields as passing\. |

## Findings and remediation

### Operating system lifecycle coverage is unconfirmed
- Description: OS lifecycle coverage is unsupported or the collected OS identity is unrecognized\.
- Finding ID: OS\_LIFECYCLE\_COVERAGE\_GAP
- Severity: Warning
- Severity meaning: Requires manual confirmation but does not necessarily indicate high risk\.
- Evidence: \{"source": "", "observed\_product": "", "observed\_version": ""\}
- Pre-change checks: Review impact scope, maintenance window, and backups before implementation
- Applicability: Current collected facts cannot establish whether support is active or ended; this is not a security pass\.
- Impact and conditions: Unknown lifecycle coverage does not establish that the system remains supported or is risk\-free\.
- Recommended steps: Verify the operating system product and version from trusted collection results, add an audited lifecycle policy record, and analyze again\.
- Rollback: This finding makes no changes\.
- Verification: Review the OS collection source, product, and version, and confirm the policy snapshot covers this identity\.
- References:

### Remote Desktop is enabled without requiring Network Level Authentication
- Description: RDP is enabled and NLA is disabled in the collected evidence; this check does not determine inbound firewall allowance or external reachability\.
- Finding ID: WIN\_BASELINE\_RDP\_NLA\_DISABLED
- Severity: Attention
- Severity meaning: Requires priority review because it may affect security, availability, or the inspection conclusion\.
- Evidence: \{"rdp\_enabled": true, "nla\_required": false, "network\_reachability\_checked": false\}
- Pre-change checks: Confirm server role, approved maintenance window, RDP client versions, remote\-account scope, and a working out\-of\-band or local recovery path\. Record the effective policy and firewall source scope\.
- Applicability: Based on current registry\-policy evidence; it does not prove that the RDP service is reachable\. Domain Group Policy and Windows version can affect the effective setting\.
- Impact and conditions: RDP provides a remote logon entry point, and disabling NLA reduces authentication protection before session establishment\. Legacy client compatibility and business dependencies may affect remediation\.
- Recommended steps: 1\. If RDP is not needed, confirm out\-of\-band or local administration and dependencies before disabling Remote Desktop\. 2\. If it is required, enable NLA according to policy and verify management client compatibility\. 3\. Review permitted remote accounts and firewall source scope; this finding is not a reachability test\.
- Rollback: If an approved legacy client is not yet compatible, the policy owner should restore the recorded NLA setting while keeping the existing management session and out\-of\-band channel\. Do not widen firewall scope as a rollback\.
- Verification: Read the effective RDP/NLA policy again\. From an approved client, establish a new session and verify account authorization and firewall source restrictions\.
- References: https://learn\.microsoft\.com/en\-us/windows\-server/remote/remote\-desktop\-services/remotepc/remote\-desktop\-allow\-access

### SMB 1\.0 is explicitly enabled
- Description: The LanmanServer SMB1 registry setting is explicitly enabled; a missing value is not treated as enabled or disabled\.
- Finding ID: WIN\_BASELINE\_SMB1\_ENABLED
- Severity: Attention
- Severity meaning: Requires priority review because it may affect security, availability, or the inspection conclusion\.
- Evidence: \{"smb1\_enabled": true, "evidence\_source": "explicit setting"\}
- Pre-change checks: Confirm SMBv2/v3 support on clients and servers, compatibility of NAS, backup, and scanning devices, the share\-service window, and recovery media\. Record the current SMB1 feature state\.
- Applicability: Triggers only when collected evidence explicitly shows SMB1 enabled\. Detection and removal controls differ by Windows version; a missing registry value remains unknown\.
- Impact and conditions: SMBv1 is an obsolete protocol and may increase file\-sharing exposure; verify dependencies of legacy devices, applications, and backups before removing it\.
- Recommended steps: 1\. Inventory SMB dialect dependencies for NAS, legacy Windows systems, scanning or backup devices, and applications\. 2\. Follow Microsoft guidance for the target OS version to remove or disable SMBv1 through Windows Features or Server Manager; confirm the change window and restart requirements first\. 3\. Do not directly edit the registry just to clear this finding\.
- Rollback: If an approved change causes compatibility failures, restore the original feature state through the supported feature\-management control for that Windows version and reboot if prompted\. Recheck dependencies; do not copy an unapproved registry template\.
- Verification: Use the supported SMB configuration query for that Windows version to verify SMB1 state\. From an approved client, test required share reads/writes and audit logging\.
- References: https://learn\.microsoft\.com/windows\-server/storage/file\-server/troubleshoot/detect\-enable\-and\-disable\-smbv1\-v2\-v3

### Windows automatic logon is enabled
- Description: The Winlogon AutoAdminLogon flag is 1; the collector does not read or export automatic logon credentials\.
- Finding ID: WIN\_BASELINE\_AUTOLOGON\_ENABLED
- Severity: Attention
- Severity meaning: Requires priority review because it may affect security, availability, or the inspection conclusion\.
- Evidence: \{"auto\_logon\_enabled": true, "credential\_value\_read": false\}
- Pre-change checks: Confirm unattended\-use requirements, physical device access controls, service\-account permissions, and credential custody\. Identify the source of configuration, such as GPO or an autologon tool\.
- Applicability: Uses only the AutoAdminLogon flag\. It does not read DefaultPassword, LSA Secret, or other credentials, and does not establish where credentials are stored\.
- Impact and conditions: Automatic logon may let someone with physical access enter the configured account's desktop and access its resources\.
- Recommended steps: 1\. Confirm whether unattended logon is needed and review physical access controls\. 2\. Without explicit business approval, have the account owner disable it through an approved method and rotate any credentials used for automatic logon\. 3\. Do not copy passwords into tickets, command lines, or inspection reports\.
- Rollback: If an approved service requires autologon, the credential owner should restore the original tool or policy through the approved process and rotate credentials\. Never restore a plaintext password in a report or script\.
- Verification: Recheck the autologon flag and effective policy\. Confirm a normal reboot no longer enters the desktop automatically and that credentials do not appear in collected files or reports\.
- References: https://learn\.microsoft\.com/en\-us/troubleshoot/windows\-server/user\-profiles\-and\-logon/turn\-on\-automatic\-logon

### Built\-in Guest account is enabled
- Description: The local account summary reports the built\-in Guest account ending in SID \-501 as enabled; account names and SIDs are not exported\.
- Finding ID: WIN\_BASELINE\_GUEST\_ENABLED
- Severity: Warning
- Severity meaning: Requires manual confirmation but does not necessarily indicate high risk\.
- Evidence: \{"built\_in\_guest\_enabled": true, "account\_name\_exported": false\}
- Pre-change checks: Check for dependencies on the Guest Only local sharing security model, legacy applications, or device integrations\. Review share permissions, approved exceptions, and an administrator account for rollback\.
- Applicability: Applies only when the local built\-in Guest SID can be identified\. Domain policy may control the state; do not conclude if account lookup fails\.
- Impact and conditions: A guest account may broaden local or share access; legacy configurations such as the Guest Only sharing model may depend on it\.
- Recommended steps: 1\. Check whether shares, services, or legacy local\-account settings depend on Guest\. 2\. If it has no approved purpose, disable the built\-in Guest account through Local Users or organizational security policy\. 3\. Review SMB share permissions and access logs to confirm Guest is not used as a business account\.
- Rollback: If business testing confirms a dependency, the policy owner should restore the recorded Guest state and re\-restrict its resource permissions\. Do not restore default share access\.
- Verification: Recollect Guest state\. Check relevant share and logon tests and security logs, and confirm an approved administrator account can still maintain the device\.
- References: https://learn\.microsoft\.com/en\-us/windows/client\-management/mdm/policy\-csp\-localpoliciessecurityoptions

### At least one Windows Firewall profile is disabled
- Description: At least one Domain, Private/Standard, or Public firewall profile has an explicit EnableFirewall value of 0\.
- Finding ID: WIN\_BASELINE\_FIREWALL\_PROFILE\_DISABLED
- Severity: Attention
- Severity meaning: Requires priority review because it may affect security, availability, or the inspection conclusion\.
- Evidence: \{"disabled\_profiles": \["PublicProfile"\]\}
- Pre-change checks: Record the disabled profile, current network type, effective GPO, firewall exceptions, remote\-management channel, and business listeners\. Schedule a maintenance window with a recovery path\.
- Applicability: Based on local profile registry evidence\. Domain policy or security products may provide other filtering layers; this result does not test network reachability\.
- Impact and conditions: A disabled profile may lack its inbound or outbound rule protections; this finding does not infer other profile states or network perimeter controls\.
- Recommended steps: 1\. Confirm the active network profile, management access, and approved inbound exceptions\. 2\. Have the firewall policy owner review Group Policy and business exceptions; if none are approved, restore the profile through Windows Defender Firewall with Advanced Security\. 3\. Verify management access and critical business connections first; do not reset all rules at once\.
- Rollback: If enabling the profile interrupts approved business traffic, the firewall administrator should restore the recorded GPO/profile and exceptions and verify the management channel\. Do not disable the firewall globally as rollback\.
- Verification: Read the effective state of all three profiles again\. Separately verify authorized management access, required business traffic, and rule logging\.
- References: https://learn\.microsoft\.com/en\-us/powershell/module/netsecurity/get\-netfirewallprofile?view=windowsserver2025\-ps

### Effective password policy does not require complexity
- Description: The secedit merged policy reports PasswordComplexity=0; this evaluates only the exported system policy and does not audit account passwords\.
- Finding ID: WIN\_BASELINE\_PASSWORD\_COMPLEXITY\_DISABLED
- Severity: Warning
- Severity meaning: Requires manual confirmation but does not necessarily indicate high risk\.
- Evidence: \{"password\_complexity": 0\}
- Pre-change checks: Confirm domain\-join state, effective GPO, fine\-grained password policies, service\-account impact, and user\-support impact\. Record policy origin and the approved baseline\.
- Applicability: A system\-level value from the merged secedit export\. AD DS fine\-grained password policies may vary by account or group and are not fully covered by this field\.
- Impact and conditions: New passwords may not be subject to Windows complexity rules and could use weaker patterns; an organization may have other approved authentication controls\.
- Recommended steps: 1\. Confirm the applicable local, domain GPO, and fine\-grained password policies with the identity or domain policy owner\. 2\. If required by policy, enable complexity in Group Policy or Local Security Policy under Account Policies → Password Policy, after checking legacy system and service account compatibility\. 3\. Follow the approved minimum length; do not reset existing passwords automatically\.
- Rollback: If validation finds compatibility impact, the policy owner should restore the recorded local/GPO value and check whether a higher\-priority domain policy overrides it\. Do not weaken other identity controls\.
- Verification: Export effective policy again and confirm the expected value\. Test the new\-password policy with an organization\-approved test account and review relevant identity\-service logs\.
- References: https://learn\.microsoft\.com/en\-us/previous\-versions/windows/it\-pro/windows\-10/security/threat\-protection/security\-policy\-settings/password\-must\-meet\-complexity\-requirements

### Effective minimum password length is below Microsoft guidance
- Description: The secedit merged policy reports MinimumPasswordLength below 8; this is a maintenance prompt, not a regulatory or organizational audit conclusion\.
- Finding ID: WIN\_BASELINE\_PASSWORD\_MINIMUM\_LENGTH\_LOW
- Severity: Warning
- Severity meaning: Requires manual confirmation but does not necessarily indicate high risk\.
- Evidence: \{"minimum\_password\_length": 6, "reference\_floor": 8\}
- Pre-change checks: Confirm effective policy origin, the organizational password baseline, user\-support capacity, service\-account and automation dependencies, and the account\-lockout recovery process\.
- Applicability: Uses the 8\-character reference minimum in Microsoft Windows 10/11 guidance\. Domain fine\-grained policies can differ by account or group and must be checked separately\.
- Impact and conditions: Short local passwords or permitted empty passwords may be easier to guess; stronger requirements can also increase lockout and compatibility support costs\.
- Recommended steps: 1\. Review domain and fine\-grained policies and system use with the identity owner\. 2\. If the applicable organizational baseline requires at least 8 characters, raise the minimum through policy management; provide passphrase guidance and assess service account and legacy application impact\. 3\. Do not treat an arbitrary number as a universal compliance threshold\.
- Rollback: If an approved change breaks service accounts or business logons, the policy owner should restore the recorded value and coordinate credential rotation\. Do not write down or share existing passwords\.
- Verification: Recollect MinimumPasswordLength\. With an approved test account, verify the new\-password policy and dependent services, and confirm no passwords appear in the report\.
- References: https://learn\.microsoft\.com/en\-us/previous\-versions/windows/it\-pro/windows\-10/security/threat\-protection/security\-policy\-settings/minimum\-password\-length

### Effective account lockout policy has no threshold
- Description: The secedit merged policy reports LockoutBadCount=0; the tool does not select a lockout threshold or duration for the organization\.
- Finding ID: WIN\_BASELINE\_ACCOUNT\_LOCKOUT\_DISABLED
- Severity: Warning
- Severity meaning: Requires manual confirmation but does not necessarily indicate high risk\.
- Evidence: \{"lockout\_threshold": 0\}
- Pre-change checks: Confirm domain/GPO and fine\-grained password policies, effects on administrator and service accounts, help\-desk unlock capacity, monitoring alerts, and the approved threshold settings\.
- Applicability: Reflects only the system\-level threshold in the merged secedit policy\. Individual domain accounts may use fine\-grained policies, so this does not determine the policy for every account\.
- Impact and conditions: Failed logons will not trigger lockout under this policy threshold, which may increase guessing opportunities; a threshold set too low can also cause false lockouts and denial of service\.
- Recommended steps: 1\. Have the identity owner assess exposure, service accounts, help desk unlock capacity, and domain policy\. 2\. Configure the approved lockout threshold, duration, and counter reset period\. 3\. Validate monitoring, unlock procedures, and automated account impact in a test scope first\.
- Rollback: If business accounts are locked unexpectedly or automation is interrupted, the identity owner should restore the recorded approved threshold and perform unlock/credential checks\. Do not relax thresholds indefinitely without approval\.
- Verification: Read effective LockoutBadCount again\. With an approved test account, verify lockout, duration, counter\-reset behavior, and unlock alerts\.
- References: https://learn\.microsoft\.com/en\-us/previous\-versions/windows/it\-pro/windows\-10/security/threat\-protection/security\-policy\-settings/account\-lockout\-policy

### Review a suspicious auto\-start service path
- Description: An automatic service binary path contains a configured high\-attention path substring\.
- Finding ID: WIN\_SERVICE\_SUSPICIOUS\_PATH
- Severity: Attention
- Severity meaning: Requires priority review because it may affect security, availability, or the inspection conclusion\.
- Evidence: \{"services": \["合成演示服务"\], "matched\_count": 1\}
- Pre-change checks: Confirm the service owner, service account, startup mode, signature, file origin, and change window\. First determine whether the service is managed by a software updater or organizational management agent\.
- Applicability: Checks only whether an automatic service executable path contains one of the limited high\-attention path fragments\. An unknown path is not evidence that the service is safe or malicious\.
- Impact and conditions: An auto\-start service located in a user or temporary directory requires close review\.
- Recommended steps: Review the service path, signature, creation time, and business origin\.
- Rollback: This tool does not stop or modify services\. If an approved change fails, the service owner should restore the recorded service configuration and file version, then verify dependencies\.
- Verification: Recollect the service name, startup mode, and sanitized path\. Verify the signature and origin, then confirm the service and dependent business functions operate normally\.
- References:

### Low disk space
- Description: Low free space was detected on a disk or volume\. This may affect system updates, log writes, applications, or retention of troubleshooting evidence\.
- Finding ID: WIN\_DISK\_LOW\_SPACE:C:
- Severity: Warning
- Severity meaning: Requires manual confirmation but does not necessarily indicate high risk\.
- Evidence: \{"source": "disks", "drive": "C:", "volume": null, "mount\_point": null, "device\_id": null, "free\_gb": 5\.0, "total\_gb": 100\.0, "free\_percent": 5\.0, "threshold": \{"free\_percent\_lte": 10\.0, "free\_gb\_lte": 10\.0\}\}
- Pre-change checks: Confirm the drive, filesystem, total and free capacity, and collection time\. Identify ownership of log, database, backup, and application directories; confirm retention policy and a business maintenance window\.
- Applicability: The threshold comes from the effective Windows risk rule\. Interpret virtual disks, quota volumes, thin\-provisioned volumes, and short\-term fluctuations in the actual platform context\.
- Impact and conditions: Very low free space can cause update failures, failed application logging, database or middleware errors, loss of troubleshooting evidence, and in severe cases reduced service stability\.
- Recommended steps: Confirm whether the affected volume holds the system or application logs, then assess both free\-space percentage and absolute capacity\. If needed, remove confirmed unnecessary files, move logs or backups, expand storage, or adjust retention\. Do not automatically delete files before confirming their purpose\.
- Rollback: This tool does not delete files or expand storage\. Record original paths, capacity, and retention policy before cleanup or migration; restore only moved files or revert an approved retention\-policy change\.
- Verification: Recollect total capacity, free capacity, and percentage for the same volume\. Check related services, log writes, and backup jobs, and confirm free space is no longer falling rapidly\.
- References:

## Evidence gaps

Analysis is incomplete; missing evidence does not mean no risk was found.
- Evidence file was only partially collected: accounts\.txt \[EVIDENCE\_PARTIAL:accounts\.txt\]
- Evidence file was only partially collected: startup\_items\.txt \[EVIDENCE\_PARTIAL:startup\_items\.txt\]
- Administrator group member count is unknown \[WINDOWS\_ADMINISTRATOR\_COUNT\_UNKNOWN\]
- Startup item record count is unknown \[WINDOWS\_STARTUP\_RECORD\_COUNT\_UNKNOWN\]
- Startup item facts are missing or unknown \[WINDOWS\_STARTUP\_FACTS\_MISSING\_OR\_UNKNOWN\]
- OS lifecycle coverage is unsupported or the identity is unrecognized

## AI-assisted suggestions (not an official conclusion)

- Status：AI\_NOT\_RUN
- AI text is separate from deterministic findings and does not change analysis status or severity.
- Reason：Local AI is opt\-in and was not requested
