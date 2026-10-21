"""Curated bilingual display text for built-in Windows and platform rules.

Pairs are fixed as (zh-CN, en-US); source wording is retained verbatim on one side.
"""
from __future__ import annotations

RULE_FINDINGS: dict[str, dict[str, tuple[str, str]]] = {'WIN_PORT_22_REVIEW': {'title': ('SSH 常用端口外部监听审查', 'Review external listener on the common SSH port'),
                        'description': ('配置的 SSH 检查端口正在 0.0.0.0 或 :: 上监听。此项只检查监听状态，不验证进程是否为 '
                                        'sshd，也不判断该访问是否符合预期。',
                                        'A configured SSH review port is listening on 0.0.0.0 or ::. This '
                                        'listener-only check does not verify that the process is sshd or '
                                        'that the access is expected.'),
                        'impact': ('对外监听的 SSH 常用端口可能扩大远程访问面，但仅凭端口监听不能确认服务身份或是否属于预期配置。',
                                   'An externally listening SSH port may expand remote access, but the '
                                   'listener alone does not establish service identity or whether the '
                                   'configuration is expected.'),
                        'precheck': ('变更前确认设备角色、SSH维护用途、当前登录路径和备用本地/带外通道；核对服务身份、sshd配置、有效防火墙规则、来源范围及组策略来源。',
                                     'Before changing anything, confirm the device role, SSH maintenance '
                                     'purpose, current logon path, and a backup local or out-of-band '
                                     'channel. Verify the service identity, sshd configuration, effective '
                                     'firewall rules, source scope, and Group Policy source.'),
                        'applicability': ('只说明配置的SSH复核端口在通配地址监听；不证明进程身份、入站规则允许或网络可达。端口22可能承载获批维护通道。',
                                          'This only indicates that the configured SSH review port listens '
                                          'on a wildcard address. It does not establish process identity, an '
                                          'inbound firewall allowance, or network reachability. Port 22 may '
                                          'carry an approved maintenance channel.'),
                        'recommendation': ('先由资产负责人确认SSH用途和监听进程。若属于获批维护通道，保留22端口并仅按批准来源范围收紧有效防火墙规则；若确认不再需要，按维护窗口通过受支持的服务/策略入口调整具体服务和规则。不要仅凭端口命中停止未知进程或阻断22。',
                                           'Have the asset owner confirm the SSH purpose and listening '
                                           'process. Keep port 22 for an approved maintenance channel and '
                                           'scope effective firewall rules to approved sources. If it is no '
                                           'longer needed, adjust the identified service and rules through '
                                           'supported management controls during a maintenance window. Do '
                                           'not stop an unknown process or block port 22 based only on this '
                                           'match.'),
                        'rollback': ('变更前记录sshd服务启动类型、配置和对应防火墙规则；若新会话失败，从本地/带外通道恢复原规则范围及服务设置，并先验证维护连接再退出备用会话。',
                                     'Record the sshd startup type, configuration, and related firewall '
                                     'rules before a change. If a new session fails, use the local or '
                                     'out-of-band channel to restore the prior rule scope and service '
                                     'settings. Verify the maintenance connection before closing the backup '
                                     'session.'),
                        'verification_checkpoint': ('复核sshd服务与配置、22端口监听及有效防火墙来源范围；从批准的维护来源建立新的SSH会话，确认原有维护路径仍可用。',
                                                    'Review the sshd service and configuration, port 22 '
                                                    'listener, and effective firewall source scope. '
                                                    'Establish a new SSH session from an approved '
                                                    'maintenance source and confirm the existing maintenance '
                                                    'path still works.')},
 'WIN_SMB_445_ALLOWED': {'title': ('SMB 常用端口外部监听审查', 'Review external listener on the common SMB port'),
                         'description': ('配置的 SMB 检查端口正在 0.0.0.0 或 :: 上监听。此项只检查监听状态，不验证防火墙允许规则或共享权限。',
                                         'A configured SMB review port is listening on 0.0.0.0 or ::. This '
                                         'listener-only check does not verify firewall Allow rules or share '
                                         'permissions.'),
                         'impact': ('对外监听的 SMB 常用端口可能形成文件共享访问面，但仅凭监听不能确认防火墙是否允许入站或共享权限是否宽泛。',
                                    'An externally listening SMB port may expose a file-sharing surface, but '
                                    'the listener alone does not establish inbound firewall allowance or '
                                    'broad share permissions.'),
                         'precheck': ('先核对获批共享清单、共享与NTFS权限、SMB服务、网络配置文件和有效入站规则；询问文件服务、备份、打印、虚拟化、集群和存储依赖，并保留当前管理通道。',
                                      'Review the approved share inventory, share and NTFS permissions, SMB '
                                      'service, network profile, and effective inbound rules. Check '
                                      'dependencies for file services, backup, printing, virtualization, '
                                      'clustering, and storage, and preserve the current management '
                                      'channel.'),
                         'applicability': ('只说明TCP 445在通配地址监听；不能证明防火墙允许、共享权限宽泛或外部可达。监听可能服务于获批的文件/打印/存储业务。',
                                           'This only indicates that TCP 445 listens on a wildcard address. '
                                           'It does not prove firewall allowance, broad share permissions, '
                                           'or external reachability. The listener may support approved '
                                           'file, print, or storage services.'),
                         'recommendation': ('由业务所有者确认445对应的共享用途和授权。若承载获批文件、打印、备份、虚拟化或集群业务，保留必要通道并核对共享/NTFS最小权限及防火墙来源范围；只有确认无依赖后，才按变更流程通过Windows受支持管理入口禁用不需要的共享服务或收紧规则。不要仅凭端口监听直接封锁445。',
                                            'Have the service owner confirm the purpose and authorization '
                                            'for port 445. Preserve required channels for approved file, '
                                            'print, backup, virtualization, or cluster workloads and review '
                                            'least-privilege share/NTFS permissions and firewall source '
                                            'scope. Only after confirming there are no dependencies, use '
                                            'supported Windows controls and change procedures to disable an '
                                            'unneeded service or tighten rules. Do not block port 445 based '
                                            'only on the listener.'),
                         'rollback': ('变更前保存共享清单、ACL、SMB服务设置和有效防火墙规则；若业务访问或备份失败，由获批管理员经本地/带外通道恢复记录的配置，并验证必要客户端的读写与维护访问。',
                                      'Save the share inventory, ACLs, SMB service settings, and effective '
                                      'firewall rules before a change. If business access or backups fail, '
                                      'an approved administrator should restore the recorded configuration '
                                      'through a local or out-of-band channel and verify required client '
                                      'read/write and maintenance access.'),
                         'verification_checkpoint': ('复核批准共享及其共享/NTFS权限、SMB服务和防火墙配置文件/来源范围；从批准客户端完成必要读写与备份/存储验证，不把本机监听当作远程可达证明。',
                                                     'Review approved shares and their share/NTFS '
                                                     'permissions, SMB service, firewall profile, and source '
                                                     'scope. From an approved client, verify required '
                                                     'read/write and backup/storage operations; do not treat '
                                                     'the local listener as proof of remote reachability.')},
 'WIN_RDP_EXPOSED_REVIEW': {'title': ('RDP 常用端口外部监听审查', 'Review external listener on the common RDP port'),
                            'description': ('配置的 RDP 检查端口正在 0.0.0.0 或 :: 上监听。此项只检查监听状态，不判断远程桌面启用状态或入站防火墙可达性。',
                                            'A configured RDP review port is listening on 0.0.0.0 or ::. '
                                            'This listener-only check does not determine the Remote Desktop '
                                            'enablement state or inbound firewall reachability.'),
                            'impact': ('对外监听的 RDP 常用端口可能形成远程登录访问面，但仅凭监听不能确认远程桌面状态或防火墙是否允许入站。',
                                       'An externally listening RDP port may expose a remote logon surface, '
                                       'but the listener alone does not establish Remote Desktop state or '
                                       'inbound firewall allowance.'),
                            'recommendation': ('人工确认监听进程及 RDP 使用意图，并另行核对远程桌面状态、防火墙配置、允许来源和账户安全；本 Finding '
                                               '不代表已确认 RDP 启用或入站允许。',
                                               'Confirm the listening process and intended RDP use. '
                                               'Separately review Remote Desktop state, firewall '
                                               'configuration, allowed sources, and account security. This '
                                               'finding does not confirm that RDP is enabled or inbound '
                                               'access is allowed.')},
 'WIN_PROXY_PORT_EXPOSED': {'title': ('代理相关端口需要复核', 'Review proxy-related listener'),
                            'description': ('7890-7899 范围内的端口正在 0.0.0.0 或 :: 上监听。仅回环监听的 Clash Verge 或 mihomo '
                                            '端口可能是本地代理提示；全接口监听需要复核。',
                                            'A port in the 7890-7899 range is listening on 0.0.0.0 or ::. '
                                            'Loopback-only Clash Verge or mihomo ports may be local proxy '
                                            'Info, but all-interface listeners require review.'),
                            'impact': ('代理端口如对局域网开放可能带来访问风险。',
                                       'A proxy port exposed to the local network may create an access '
                                       'risk.'),
                            'recommendation': ('确认是否有意向局域网开放；如非预期，请检查代理应用的绑定地址和访问控制。',
                                               'Confirm whether LAN exposure is intended. If not intended, '
                                               "review the proxy application's bind address and access "
                                               'control.')},
 'WIN_ADMINISTRATOR_COUNT_REVIEW': {'title': ('管理员组成员较多', 'Large number of Administrators group members'),
                                    'description': ('管理员组成员超过了配置的复核阈值。',
                                                    'The Administrators group contains more members than the '
                                                    'configured review threshold.'),
                                    'impact': ('管理员面扩大，误用或滥用风险增加。',
                                               'A larger administrator group increases the risk of '
                                               'accidental or unauthorized use.'),
                                    'precheck': ('由资产负责人先取得经批准的本地 Administrators '
                                                 '成员清单，区分个人账户、服务账户和域组；核对应急管理员及远程维护路径。报告仅保存成员数，不导出名称。',
                                                 'Have the asset owner provide an approved list of direct '
                                                 'local Administrators members. Distinguish personal '
                                                 'accounts, service accounts, and domain groups; verify '
                                                 'emergency administrators and remote maintenance paths. The '
                                                 'report stores only the member count, not names.'),
                                    'applicability': ('仅比较本地内置 Administrators '
                                                      '组直接成员数与示例规则阈值；不代表账户滥用、域组展开结果或组织合规结论。查询失败时保留 UNKNOWN。',
                                                      'Compares only the direct member count of the local '
                                                      'built-in Administrators group with the example-rule '
                                                      'threshold. It does not establish account abuse, '
                                                      'expanded domain-group membership, or organizational '
                                                      'compliance. Preserve UNKNOWN if the query fails.'),
                                    'recommendation': ('人工复核管理员组成员是否均为预期账户。',
                                                       'Manually verify that every Administrators group '
                                                       'member is expected.'),
                                    'rollback': ('本工具不修改成员关系；若后续获批调整造成维护受阻，由授权管理员按变更前审批记录恢复必要成员并验证应急访问。',
                                                 'This tool does not change group membership. If a later '
                                                 'approved adjustment disrupts maintenance, an authorized '
                                                 'administrator should restore necessary members using the '
                                                 'pre-change approval record and verify emergency access.'),
                                    'verification_checkpoint': ('重新采集本地管理员成员数；授权人员逐项复核成员用途、审批和最小权限，确认应急维护入口可用。',
                                                                'Recollect the local administrator count. '
                                                                'Authorized personnel should review each '
                                                                'member purpose, approval, and least '
                                                                'privilege, and confirm that the emergency '
                                                                'maintenance path works.')},
 'WIN_SERVICE_SUSPICIOUS_PATH': {'title': ('可疑自启动服务路径', 'Review a suspicious auto-start service path'),
                                 'description': ('自动启动服务的二进制路径包含配置的高关注路径片段。',
                                                 'An automatic service binary path contains a configured '
                                                 'high-attention path substring.'),
                                 'impact': ('用户目录或临时目录中的自启动服务需要高度关注。',
                                            'An auto-start service located in a user or temporary directory '
                                            'requires close review.'),
                                 'precheck': ('核对服务业务所有者、服务账户、启动方式、签名、文件来源和变更窗口；先确认是否由软件更新器或组织管理代理托管。',
                                              'Confirm the service owner, service account, startup mode, '
                                              'signature, file origin, and change window. First determine '
                                              'whether the service is managed by a software updater or '
                                              'organizational management agent.'),
                                 'applicability': ('只检查自动启动服务的可执行文件路径是否包含有限高关注路径片段；路径未知时不推断安全或恶意。',
                                                   'Checks only whether an automatic service executable path '
                                                   'contains one of the limited high-attention path '
                                                   'fragments. An unknown path is not evidence that the '
                                                   'service is safe or malicious.'),
                                 'recommendation': ('复核服务路径、签名、创建时间和业务来源。',
                                                    'Review the service path, signature, creation time, and '
                                                    'business origin.'),
                                 'rollback': ('本工具不停止或修改服务；获批变更失败时，由服务负责人按记录恢复原服务配置和文件版本并验证依赖。',
                                              'This tool does not stop or modify services. If an approved '
                                              'change fails, the service owner should restore the recorded '
                                              'service configuration and file version, then verify '
                                              'dependencies.'),
                                 'verification_checkpoint': ('重新采集服务名称、启动方式和脱敏路径；核对签名/来源，并验证服务及依赖业务恢复正常。',
                                                             'Recollect the service name, startup mode, and '
                                                             'sanitized path. Verify the signature and '
                                                             'origin, then confirm the service and dependent '
                                                             'business functions operate normally.')},
 'WIN_SCHEDULED_TASK_SUSPICIOUS_PATH': {'title': ('计划任务路径需要复核', 'Review a scheduled task path'),
                                        'description': ('计划任务操作包含配置的高关注路径片段。',
                                                        'A scheduled task action contains a configured '
                                                        'high-attention path substring.'),
                                        'impact': ('用户目录或临时目录启动项可能是持久化线索。',
                                                   'Review the specific evidence and intended business use '
                                                   'with the responsible owner before making any approved '
                                                   'change.'),
                                        'recommendation': ('人工复核任务 Action 路径、签名和创建来源。',
                                                           'Manually review the task action path, signature, '
                                                           'and creation source.')},
 'WIN_EVENT_LOG_ERROR_VOLUME': {'title': ('近期系统事件异常较多', 'High volume of recent system events'),
                                'description': ('当前事件日志采集窗口中存在严重事件，或达到配置的错误数量阈值。',
                                                'The current event-log collector window contains a critical '
                                                'event or reaches the configured error-count threshold.'),
                                'impact': ('系统稳定性或驱动/服务可能存在异常。',
                                           'System stability or a driver or service may be affected.'),
                                'recommendation': ('查看事件日志详情，按 Provider 和 Event ID 继续定位。',
                                                   'Review event log details and investigate by provider and '
                                                   'event ID.')},
 'WIN_STARTUP_SUSPICIOUS_PATH': {'title': ('启动项存在高关注路径或脚本解释器线索',
                                           'Startup item contains a high-attention path or script '
                                           'interpreter clue'),
                                 'description': ('检测到启动项路径或命令包含需要人工复核的持久化线索。',
                                                 'A startup path or command contains a persistence clue that '
                                                 'requires manual review.'),
                                 'impact': ('该启动项可能是正常软件，也可能是异常持久化入口，需要结合签名、来源和用户确认判断。',
                                            'The startup item may be legitimate software or an unexpected '
                                            'persistence entry; review its signature, origin, and user '
                                            'intent.'),
                                 'precheck': ('核对启动项所有者、来源位置、脱敏后的映像/脚本路径和签名；确认是否为组织批准的登录脚本、管理代理或安全产品，避免仅凭解释器名称停用。',
                                              'Confirm the startup item owner, source location, sanitized '
                                              'image or script path, and signature. Determine whether it is '
                                              'an approved logon script, management agent, or security '
                                              'product; do not disable it based only on an interpreter '
                                              'name.'),
                                 'applicability': ('命中可调整规则中的高关注目录、解释器或脚本扩展名；采集器不导出启动命令参数和账户名，未知映像路径会形成证据缺口。',
                                                   'Matches a configurable high-attention directory, '
                                                   'interpreter, or script extension. The collector does not '
                                                   'export command arguments or account names; an unknown '
                                                   'image path is an evidence gap.'),
                                 'recommendation': ('人工确认启动项来源；如不认识该项，进一步检查文件签名、创建时间和父目录。',
                                                    "Confirm the startup item's origin. If it is unfamiliar, "
                                                    'inspect the file signature, creation time, and parent '
                                                    'directory.'),
                                 'rollback': ('本工具不禁用或删除启动项；如获批调整导致登录或管理功能异常，按变更前记录恢复对应注册表项/启动文件并验证登录流程。',
                                              'This tool does not disable or delete startup items. If an '
                                              'approved adjustment disrupts logon or management, restore the '
                                              'recorded registry entry or startup file and verify the logon '
                                              'flow.'),
                                 'verification_checkpoint': ('复采启动项并核对签名、文件来源和触发范围；验证登录、业务启动与安全产品状态，确认参数/账户名未进入证据包。',
                                                             'Recollect the startup item and verify its '
                                                             'signature, file origin, and trigger scope. '
                                                             'Test logon, business startup, and '
                                                             'security-product status; confirm arguments and '
                                                             'account names are absent from the evidence '
                                                             'package.')},
 'WIN_DISK_LOW_SPACE': {'title': ('磁盘剩余空间偏低', 'Low disk space'),
                        'description': ('检测到磁盘或卷剩余空间偏低，可能影响系统更新、日志写入、应用运行或故障排查留存能力。',
                                        'Low free space was detected on a disk or volume. This may affect '
                                        'system updates, log writes, applications, or retention of '
                                        'troubleshooting evidence.'),
                        'impact': ('剩余空间过低可能导致系统更新失败、应用写日志失败、数据库或中间件异常、排障证据丢失，严重时可能影响服务稳定性。',
                                   'Very low free space can cause update failures, failed application '
                                   'logging, database or middleware errors, loss of troubleshooting '
                                   'evidence, and in severe cases reduced service stability.'),
                        'precheck': ('确认盘符、文件系统、总容量、可用容量和采集时间；核对日志、数据库、备份及应用目录归属，确认保留策略和业务维护窗口。',
                                     'Confirm the drive, filesystem, total and free capacity, and collection '
                                     'time. Identify ownership of log, database, backup, and application '
                                     'directories; confirm retention policy and a business maintenance '
                                     'window.'),
                        'applicability': ('阈值来自当前生效的 Windows 风险规则；虚拟盘、配额卷、精简置备卷及短时波动需结合平台实际解释。',
                                          'The threshold comes from the effective Windows risk rule. '
                                          'Interpret virtual disks, quota volumes, thin-provisioned volumes, '
                                          'and short-term fluctuations in the actual platform context.'),
                        'recommendation': ('请人工确认受影响卷是否为系统盘或应用日志盘，并结合剩余空间百分比和绝对剩余容量评估；必要时清理无用文件、迁移日志或备份、扩容磁盘或调整保留策略。不要在未确认业务用途前自动删除文件。',
                                           'Confirm whether the affected volume holds the system or '
                                           'application logs, then assess both free-space percentage and '
                                           'absolute capacity. If needed, remove confirmed unnecessary '
                                           'files, move logs or backups, expand storage, or adjust '
                                           'retention. Do not automatically delete files before confirming '
                                           'their purpose.'),
                        'rollback': ('本工具不删除文件或扩容磁盘。清理或迁移前记录原路径、容量和保留策略；仅恢复已移动文件或回退经审批的保留策略变更。',
                                     'This tool does not delete files or expand storage. Record original '
                                     'paths, capacity, and retention policy before cleanup or migration; '
                                     'restore only moved files or revert an approved retention-policy '
                                     'change.'),
                        'verification_checkpoint': ('重新采集同一卷的总容量、可用容量与百分比；检查相关服务、日志写入和备份任务，并确认空间不再快速下降。',
                                                    'Recollect total capacity, free capacity, and percentage '
                                                    'for the same volume. Check related services, log '
                                                    'writes, and backup jobs, and confirm free space is no '
                                                    'longer falling rapidly.')},
 'WIN_BITLOCKER_NEED_ADMIN': {'title': ('BitLocker 状态需要管理员权限确认',
                                        'BitLocker status requires administrator review'),
                              'description': ('当前权限不足，无法完整确认 BitLocker 状态。',
                                              'Insufficient permissions to fully verify BitLocker status.'),
                              'impact': ('无法判断磁盘加密状态，需管理员权限复核。',
                                         'Disk encryption status cannot be determined and requires '
                                         'administrator review.'),
                              'precheck': ('确认资产负责人已批准只读复核、卷范围和维护窗口；不导出恢复密钥，不暂停保护器，不解密卷。',
                                           'Confirm the asset owner approved read-only review, the volume '
                                           'scope, and the maintenance window. Do not export recovery keys, '
                                           'suspend protectors, or decrypt volumes.'),
                              'applicability': ('仅表示当前权限无法确认 BitLocker 状态；不代表卷未加密或配置异常。',
                                                'Indicates only that current permissions were insufficient '
                                                'to verify BitLocker status. It does not mean the volume is '
                                                'unencrypted or misconfigured.'),
                              'recommendation': ('由获批管理员以只读方式核对 BitLocker '
                                                 '卷状态；若权限暂不可用，保留此证据缺口并交接复核，不要为巡检启停加密或请求工具自动提权。',
                                                 'An authorized administrator should verify BitLocker volume '
                                                 'status in read-only mode. If access is unavailable, retain '
                                                 'this evidence gap for follow-up; do not enable or disable '
                                                 'encryption or request automatic elevation for inspection.'),
                              'rollback': ('本工具只读且未修改 '
                                           'BitLocker，无需系统回滚。若复核期间按审批临时委派了读取权限，复核完成后撤销该临时授权并恢复原访问基线；不要因此暂停保护器或解密卷。',
                                           'This tool is read-only and made no BitLocker changes, so no '
                                           'system rollback is needed. If temporary read permission was '
                                           'delegated with approval, revoke it after review and restore the '
                                           'prior access baseline. Do not suspend protectors or decrypt a '
                                           'volume.'),
                              'verification_checkpoint': ('授权管理员只读运行 Get-BitLockerVolume，核对 '
                                                          'VolumeStatus、ProtectionStatus 和 '
                                                          'EncryptionPercentage（不导出恢复密钥），随后重跑只读巡检确认该权限缺口已消失。',
                                                          'An authorized administrator should run '
                                                          'Get-BitLockerVolume read-only and review '
                                                          'VolumeStatus, ProtectionStatus, and '
                                                          'EncryptionPercentage without exporting recovery '
                                                          'keys. Then rerun the read-only inspection to '
                                                          'confirm the permission gap is resolved.')},
 'WIN_SECURITY_VENDOR_PRESENT': {'title': ('检测到安全软件或电脑管家组件', 'Security software or system utility detected'),
                                 'description': ('检测到相关安全软件或电脑管家组件，存在不等于恶意，需要确认是否为用户主动安装以及是否与其他安全软件冲突。',
                                                 'Related security software or system utility components '
                                                 'were detected. Their presence does not mean they are '
                                                 'malicious; confirm whether the user installed them and '
                                                 'whether they conflict with other security software.'),
                                 'impact': ('多个安全防护或管家组件可能产生资源占用、拦截冲突或配置覆盖，但单独存在不表示异常。',
                                            'Multiple security or system utility components may consume '
                                            'resources, conflict in blocking, or override settings, but '
                                            'their presence alone is not abnormal.'),
                                 'recommendation': ('确认相关产品是否为用户主动安装、是否仍在使用，以及是否与其他安全软件存在冲突；不要自动卸载或删除。',
                                                    'Confirm whether the product was intentionally '
                                                    'installed, is still used, or conflicts with other '
                                                    'security software. Do not uninstall or delete it '
                                                    'automatically.')},
 'WIN_SECURITY_VENDOR_RESIDUE': {'title': ('检测到安全软件卸载残留',
                                           'Possible security software uninstall residue detected'),
                                 'description': ('卸载项中未发现对应产品，但仍存在服务、驱动、计划任务、启动项等残留线索，需要人工确认。',
                                                 'The product was not found in uninstall entries, but '
                                                 'service, driver, scheduled task, or startup evidence '
                                                 'remains and requires manual review.'),
                                 'impact': ('残留组件可能继续启动、占用资源或影响系统与其他安全软件，但仅凭该线索不能判断为恶意。',
                                            'Residual components may continue to run, consume resources, or '
                                            'affect the system and other security software; this evidence '
                                            'alone does not establish malicious activity.'),
                                 'precheck': ('核对产品名称/版本、卸载记录和匹配到的服务/驱动/任务/启动项状态及来源；在Windows安全中心确认当前防病毒提供程序和状态，并确认业务负责人、获批替代防护及厂商支持渠道。',
                                              'Review the product name/version, uninstall record, and state '
                                              'and origin of matching services, drivers, tasks, or startup '
                                              'items. Check the current antivirus provider and state in '
                                              'Windows Security; confirm the business owner, approved '
                                              'replacement protection, and vendor support path.'),
                                 'applicability': ('仅表示未找到对应卸载项但仍有产品线索；不能据此判断组件恶意、失效或与现有防护冲突。目录痕迹单独不构成卸载残留结论。',
                                                   'Indicates that no matching uninstall entry was found '
                                                   'while product-related clues remain. This alone does not '
                                                   'show that a component is malicious, inactive, or '
                                                   'conflicting with current protection; a directory trace '
                                                   'alone is not proof of uninstall residue.'),
                                 'recommendation': ('先确认产品是否仍安装、注册或承担防护职责；若确属卸载残留，由资产负责人确认替代防护已就绪，再使用该产品厂商发布的对应版本卸载/清理流程。不要手工删除驱动、服务、注册表项或目录；完成后检查Windows安全中心显示的提供程序与状态。',
                                                    'First confirm whether the product is still installed, '
                                                    'registered, or providing protection. If it is uninstall '
                                                    'residue, have the asset owner confirm replacement '
                                                    "protection is ready, then use the vendor's removal "
                                                    'procedure for the matching version. Do not manually '
                                                    'delete drivers, services, registry entries, or '
                                                    'directories. Afterward, check providers and status in '
                                                    'Windows Security.'),
                                 'rollback': ('本工具不删除或禁用组件。厂商清理导致启动、网络或防护异常时，按该厂商支持的恢复/重装流程及组织基线恢复，不手工回填驱动或注册表；必要时先经批准恢复可用的防护产品。',
                                              'This tool does not delete or disable components. If vendor '
                                              'cleanup causes startup, network, or protection problems, '
                                              'restore using the vendor-supported recovery or reinstall '
                                              'process and organizational baseline. Do not manually recreate '
                                              'drivers or registry entries; restore working protection with '
                                              'approval if needed.'),
                                 'verification_checkpoint': ('按厂商流程完成处理并重启（仅当其要求时），复采服务/驱动/任务/启动项；在Windows安全中心核对当前防病毒提供程序和保护状态，并验证关键业务及网络启动正常。',
                                                             'Complete the vendor procedure and reboot only '
                                                             'if it requires one. Recollect services, '
                                                             'drivers, tasks, and startup items; verify the '
                                                             'antivirus provider and protection state in '
                                                             'Windows Security, plus critical business and '
                                                             'network startup.')},
 'WIN_SECURITY_VENDOR_DRIVER_REVIEW': {'title': ('检测到安全软件相关驱动', 'Security software-related driver detected'),
                                       'description': ('检测到安全软件相关驱动或驱动残留，驱动存在不等于异常，不建议自动删除，需要确认签名、状态、启动类型和文件路径。',
                                                       'A security software-related driver or residual '
                                                       'driver was detected. Its presence alone is not '
                                                       'abnormal; do not delete it automatically. Verify its '
                                                       'signature, state, start mode, and path.'),
                                       'impact': ('相关驱动可能参与文件、网络或系统启动过滤，错误处置可能影响系统稳定性。',
                                                  'The driver may filter files, network traffic, or system '
                                                  'startup; incorrect handling may affect system stability.'),
                                       'recommendation': ('请人工确认驱动签名、运行状态、启动类型、文件路径和对应产品状态，不要自动删除或禁用。',
                                                          'Manually verify the driver signature, running '
                                                          'state, start mode, file path, and associated '
                                                          'product state. Do not delete or disable it '
                                                          'automatically.')},
 'WIN_BASELINE_RDP_NLA_DISABLED': {'title': ('已启用远程桌面但未要求网络级别身份验证',
                                             'Remote Desktop is enabled without requiring Network Level '
                                             'Authentication'),
                                   'description': ('采集到 RDP 已启用且 NLA 未启用；此项不判断防火墙是否允许入站或外部网络是否可达。',
                                                   'RDP is enabled and NLA is disabled in the collected '
                                                   'evidence; this check does not determine inbound firewall '
                                                   'allowance or external reachability.'),
                                   'impact': ('启用 RDP 会提供远程登录入口；关闭 NLA 会降低会话建立前的身份验证保护。旧客户端兼容性和业务依赖可能影响处置方式。',
                                              'RDP provides a remote logon entry point, and disabling NLA '
                                              'reduces authentication protection before session '
                                              'establishment. Legacy client compatibility and business '
                                              'dependencies may affect remediation.'),
                                   'precheck': ('确认服务器角色、获批维护窗口、RDP '
                                                '客户端版本、远程账户范围及可用的带外/本地回滚通道；记录当前有效策略和防火墙来源。',
                                                'Confirm server role, approved maintenance window, RDP '
                                                'client versions, remote-account scope, and a working '
                                                'out-of-band or local recovery path. Record the effective '
                                                'policy and firewall source scope.'),
                                   'applicability': ('来自当前注册表策略事实；不证明 RDP 服务可达。域组策略和操作系统版本可能影响有效配置。',
                                                     'Based on current registry-policy evidence; it does not '
                                                     'prove that the RDP service is reachable. Domain Group '
                                                     'Policy and Windows version can affect the effective '
                                                     'setting.'),
                                   'recommendation': ('1. 若业务不需要 RDP，在确认带外/本地管理通道和依赖后关闭远程桌面。2. 若业务需要 '
                                                      'RDP，按组织策略启用 NLA，并确认所有运维客户端兼容。3. '
                                                      '复核允许的远程账户和防火墙来源范围；不要把本 Finding 当作网络可达性测试。',
                                                      '1. If RDP is not needed, confirm out-of-band or local '
                                                      'administration and dependencies before disabling '
                                                      'Remote Desktop. 2. If it is required, enable NLA '
                                                      'according to policy and verify management client '
                                                      'compatibility. 3. Review permitted remote accounts '
                                                      'and firewall source scope; this finding is not a '
                                                      'reachability test.'),
                                   'rollback': ('若批准的旧客户端暂不兼容，由策略负责人恢复已记录的原 NLA '
                                                '设置，并保留现有管理会话和带外通道；不得为回滚扩大防火墙范围。',
                                                'If an approved legacy client is not yet compatible, the '
                                                'policy owner should restore the recorded NLA setting while '
                                                'keeping the existing management session and out-of-band '
                                                'channel. Do not widen firewall scope as a rollback.'),
                                   'verification_checkpoint': ('重新读取有效 RDP/NLA '
                                                               '策略；从获批客户端建立新会话并确认账户授权与防火墙来源限制。',
                                                               'Read the effective RDP/NLA policy again. '
                                                               'From an approved client, establish a new '
                                                               'session and verify account authorization and '
                                                               'firewall source restrictions.')},
 'WIN_BASELINE_SMB1_ENABLED': {'title': ('检测到 SMB 1.0 显式启用', 'SMB 1.0 is explicitly enabled'),
                               'description': ('LanmanServer SMB1 注册表设置明确为启用；缺失该值不会被当作关闭或开启。',
                                               'The LanmanServer SMB1 registry setting is explicitly '
                                               'enabled; a missing value is not treated as enabled or '
                                               'disabled.'),
                               'impact': ('SMBv1 是旧协议，启用可能增加文件共享攻击面；移除前必须核实旧设备、应用和备份依赖。',
                                          'SMBv1 is an obsolete protocol and may increase file-sharing '
                                          'exposure; verify dependencies of legacy devices, applications, '
                                          'and backups before removing it.'),
                               'precheck': ('确认客户端和服务端 SMBv2/SMBv3 能力、NAS/备份/扫描设备兼容性、共享业务窗口及恢复介质；记录当前 SMB1 '
                                            '功能状态。',
                                            'Confirm SMBv2/v3 support on clients and servers, compatibility '
                                            'of NAS, backup, and scanning devices, the share-service window, '
                                            'and recovery media. Record the current SMB1 feature state.'),
                               'applicability': ('仅当采集到 SMB1 明确启用时触发。不同 Windows 版本的检测和移除入口不同，缺失注册表值保持未知。',
                                                 'Triggers only when collected evidence explicitly shows '
                                                 'SMB1 enabled. Detection and removal controls differ by '
                                                 'Windows version; a missing registry value remains '
                                                 'unknown.'),
                               'recommendation': ('1. 盘点 NAS、旧 Windows、扫描/备份设备和应用的 SMB 方言依赖。2. 在目标系统版本对应的 '
                                                  'Windows Features/Server Manager 中按 Microsoft 指南移除或禁用 '
                                                  'SMBv1；执行前确认变更窗口和重启要求。3. 不要仅为消除此项直接改写注册表。',
                                                  '1. Inventory SMB dialect dependencies for NAS, legacy '
                                                  'Windows systems, scanning or backup devices, and '
                                                  'applications. 2. Follow Microsoft guidance for the target '
                                                  'OS version to remove or disable SMBv1 through Windows '
                                                  'Features or Server Manager; confirm the change window and '
                                                  'restart requirements first. 3. Do not directly edit the '
                                                  'registry just to clear this finding.'),
                               'rollback': ('如获批变更导致兼容故障，使用该 Windows '
                                            '版本支持的功能管理入口恢复原组件状态并按提示重启；之后重新核验依赖，不复制未经批准的注册表模板。',
                                            'If an approved change causes compatibility failures, restore '
                                            'the original feature state through the supported '
                                            'feature-management control for that Windows version and reboot '
                                            'if prompted. Recheck dependencies; do not copy an unapproved '
                                            'registry template.'),
                               'verification_checkpoint': ('用该版本支持的 SMB 配置查询确认 SMB1 '
                                                           '状态，并用获批客户端验证必要的共享读写和审计日志。',
                                                           'Use the supported SMB configuration query for '
                                                           'that Windows version to verify SMB1 state. From '
                                                           'an approved client, test required share '
                                                           'reads/writes and audit logging.')},
 'WIN_BASELINE_AUTOLOGON_ENABLED': {'title': ('Windows 自动登录已启用', 'Windows automatic logon is enabled'),
                                    'description': ('Winlogon AutoAdminLogon 标志为 1；采集器不读取或导出自动登录凭据。',
                                                    'The Winlogon AutoAdminLogon flag is 1; the collector '
                                                    'does not read or export automatic logon credentials.'),
                                    'impact': ('自动登录可能让能接触设备的人直接进入配置账户的桌面及其可访问资源。',
                                               'Automatic logon may let someone with physical access enter '
                                               "the configured account's desktop and access its resources."),
                                    'precheck': ('确认无人值守用途、设备物理访问控制、服务账户权限和凭据保管责任；先识别 GPO/自动登录工具的配置来源。',
                                                 'Confirm unattended-use requirements, physical device '
                                                 'access controls, service-account permissions, and '
                                                 'credential custody. Identify the source of configuration, '
                                                 'such as GPO or an autologon tool.'),
                                    'applicability': ('只根据 AutoAdminLogon 标志判断；不读取 DefaultPassword、LSA '
                                                      'Secret 或其他凭据，也不证明凭据存储位置。',
                                                      'Uses only the AutoAdminLogon flag. It does not read '
                                                      'DefaultPassword, LSA Secret, or other credentials, '
                                                      'and does not establish where credentials are stored.'),
                                    'recommendation': ('1. 确认该设备是否确需无人值守登录及其物理/机房访问控制。2. '
                                                       '若无明确业务授权，由账户/凭据负责人通过组织批准的自动登录管理方式关闭，并轮换可能用于自动登录的凭据。3. '
                                                       '不要把密码复制到工单、命令行或巡检报告。',
                                                       '1. Confirm whether unattended logon is needed and '
                                                       'review physical access controls. 2. Without explicit '
                                                       'business approval, have the account owner disable it '
                                                       'through an approved method and rotate any '
                                                       'credentials used for automatic logon. 3. Do not copy '
                                                       'passwords into tickets, command lines, or inspection '
                                                       'reports.'),
                                    'rollback': ('如获批服务确需自动登录，由凭据负责人按批准流程恢复原工具/策略并轮换凭据；不要在报告或脚本中恢复明文密码。',
                                                 'If an approved service requires autologon, the credential '
                                                 'owner should restore the original tool or policy through '
                                                 'the approved process and rotate credentials. Never restore '
                                                 'a plaintext password in a report or script.'),
                                    'verification_checkpoint': ('重新检查自动登录标志和有效策略；确认普通重启后不再自动进入桌面，凭据未出现在采集文件或报告中。',
                                                                'Recheck the autologon flag and effective '
                                                                'policy. Confirm a normal reboot no longer '
                                                                'enters the desktop automatically and that '
                                                                'credentials do not appear in collected '
                                                                'files or reports.')},
 'WIN_BASELINE_GUEST_ENABLED': {'title': ('内置 Guest 账户已启用', 'Built-in Guest account is enabled'),
                                'description': ('本地账户摘要中 SID 末尾为 -501 的内置 Guest 账户处于启用状态；不会导出账户名或 SID。',
                                                'The local account summary reports the built-in Guest '
                                                'account ending in SID -501 as enabled; account names and '
                                                'SIDs are not exported.'),
                                'impact': ('访客账户可能扩大本地或共享访问面；Guest Only 共享模型等旧配置也可能依赖它。',
                                           'A guest account may broaden local or share access; legacy '
                                           'configurations such as the Guest Only sharing model may depend '
                                           'on it.'),
                                'precheck': ('确认是否使用 Guest Only 的本地共享安全模型、旧应用或设备集成；检查共享权限、例外审批和回滚管理员账户。',
                                             'Check for dependencies on the Guest Only local sharing '
                                             'security model, legacy applications, or device integrations. '
                                             'Review share permissions, approved exceptions, and an '
                                             'administrator account for rollback.'),
                                'applicability': ('仅适用于能识别本地内置 Guest SID 的系统；域策略可能控制该状态，账户查询失败时不下结论。',
                                                  'Applies only when the local built-in Guest SID can be '
                                                  'identified. Domain policy may control the state; do not '
                                                  'conclude if account lookup fails.'),
                                'recommendation': ('1. 核对 Guest 账户是否被共享、服务或旧版本地账户模式依赖。2. '
                                                   '若无批准用途，在本地用户管理或组织安全策略中禁用内置 Guest。3. 复核 SMB '
                                                   '共享权限和访问日志，确认没有将 Guest 当作业务账户使用。',
                                                   '1. Check whether shares, services, or legacy '
                                                   'local-account settings depend on Guest. 2. If it has no '
                                                   'approved purpose, disable the built-in Guest account '
                                                   'through Local Users or organizational security policy. '
                                                   '3. Review SMB share permissions and access logs to '
                                                   'confirm Guest is not used as a business account.'),
                                'rollback': ('如业务验证证明有依赖，由策略负责人恢复已记录的 Guest 状态并重新限制其资源权限；避免恢复默认共享访问。',
                                             'If business testing confirms a dependency, the policy owner '
                                             'should restore the recorded Guest state and re-restrict its '
                                             'resource permissions. Do not restore default share access.'),
                                'verification_checkpoint': ('重新采集 Guest 状态；检查相关共享/登录测试和安全日志，确认获批管理账户仍可维护设备。',
                                                            'Recollect Guest state. Check relevant share and '
                                                            'logon tests and security logs, and confirm an '
                                                            'approved administrator account can still '
                                                            'maintain the device.')},
 'WIN_BASELINE_FIREWALL_PROFILE_DISABLED': {'title': ('至少一个 Windows 防火墙配置文件已关闭',
                                                      'At least one Windows Firewall profile is disabled'),
                                            'description': ('至少一个 Domain、Private/Standard 或 Public '
                                                            '防火墙配置文件的显式 EnableFirewall 值为 0。',
                                                            'At least one Domain, Private/Standard, or '
                                                            'Public firewall profile has an explicit '
                                                            'EnableFirewall value of 0.'),
                                            'impact': ('关闭中的配置文件可能缺少对应入站/出站规则保护；本项不推断其他配置文件状态或网络边界设备控制。',
                                                       'A disabled profile may lack its inbound or outbound '
                                                       'rule protections; this finding does not infer other '
                                                       'profile states or network perimeter controls.'),
                                            'precheck': ('记录关闭的配置文件、当前网络类型、有效 '
                                                         'GPO、防火墙例外、远程管理通道和业务监听端口；安排可恢复的维护窗口。',
                                                         'Record the disabled profile, current network type, '
                                                         'effective GPO, firewall exceptions, '
                                                         'remote-management channel, and business listeners. '
                                                         'Schedule a maintenance window with a recovery '
                                                         'path.'),
                                            'applicability': ('基于本机配置文件注册表事实；域策略或安全产品可能提供其他过滤层，本结果不做网络可达性验证。',
                                                              'Based on local profile registry evidence. '
                                                              'Domain policy or security products may '
                                                              'provide other filtering layers; this result '
                                                              'does not test network reachability.'),
                                            'recommendation': ('1. 确认当前网络配置文件、管理入口和已批准的入站例外。2. '
                                                               '由防火墙策略负责人检查组策略及业务例外；无批准例外时在 Windows Defender '
                                                               '防火墙高级安全管理中恢复对应配置文件。3. '
                                                               '先验证运维通道和关键业务连接，不要一键重置全部规则。',
                                                               '1. Confirm the active network profile, '
                                                               'management access, and approved inbound '
                                                               'exceptions. 2. Have the firewall policy '
                                                               'owner review Group Policy and business '
                                                               'exceptions; if none are approved, restore '
                                                               'the profile through Windows Defender '
                                                               'Firewall with Advanced Security. 3. Verify '
                                                               'management access and critical business '
                                                               'connections first; do not reset all rules at '
                                                               'once.'),
                                            'rollback': ('若恢复配置文件中断获批业务，由防火墙管理员恢复已记录的原 '
                                                         'GPO/配置文件与例外，并验证管理通道；不要全局关闭防火墙作为回退。',
                                                         'If enabling the profile interrupts approved '
                                                         'business traffic, the firewall administrator '
                                                         'should restore the recorded GPO/profile and '
                                                         'exceptions and verify the management channel. Do '
                                                         'not disable the firewall globally as rollback.'),
                                            'verification_checkpoint': ('重新读取三个配置文件的有效状态，并分别验证授权管理入口、必要业务流量和规则日志。',
                                                                        'Read the effective state of all '
                                                                        'three profiles again. Separately '
                                                                        'verify authorized management '
                                                                        'access, required business traffic, '
                                                                        'and rule logging.')},
 'WIN_BASELINE_PASSWORD_COMPLEXITY_DISABLED': {'title': ('有效密码策略未启用复杂性要求',
                                                         'Effective password policy does not require '
                                                         'complexity'),
                                               'description': ('secedit 合并策略显示 '
                                                               'PasswordComplexity=0；仅评估当前导出的系统策略，不审计账户口令本身。',
                                                               'The secedit merged policy reports '
                                                               'PasswordComplexity=0; this evaluates only '
                                                               'the exported system policy and does not '
                                                               'audit account passwords.'),
                                               'impact': ('新设密码可能不受 Windows 复杂性规则约束，容易采用较弱模式；组织可有经批准的其他认证控制。',
                                                          'New passwords may not be subject to Windows '
                                                          'complexity rules and could use weaker patterns; '
                                                          'an organization may have other approved '
                                                          'authentication controls.'),
                                               'precheck': ('确认域加入状态、有效 '
                                                            'GPO、细粒度密码策略、服务账户与用户支持影响；记录当前策略来源和批准基线。',
                                                            'Confirm domain-join state, effective GPO, '
                                                            'fine-grained password policies, service-account '
                                                            'impact, and user-support impact. Record policy '
                                                            'origin and the approved baseline.'),
                                               'applicability': ('secedit 合并导出中的系统级值；AD DS '
                                                                 '细粒度密码策略可按账户/组不同，不能由本字段完整覆盖。',
                                                                 'A system-level value from the merged '
                                                                 'secedit export. AD DS fine-grained '
                                                                 'password policies may vary by account or '
                                                                 'group and are not fully covered by this '
                                                                 'field.'),
                                               'recommendation': ('1. 与身份/域策略负责人确认本机、域 GPO '
                                                                  '和细粒度密码策略的实际适用范围。2. '
                                                                  '若组织基线要求，在组策略或本地安全策略的“账户策略 → '
                                                                  '密码策略”中启用复杂性要求，并先验证旧系统/服务账户兼容性。3. '
                                                                  '结合组织批准的最小长度要求，不自动重置现有密码。',
                                                                  '1. Confirm the applicable local, domain '
                                                                  'GPO, and fine-grained password policies '
                                                                  'with the identity or domain policy owner. '
                                                                  '2. If required by policy, enable '
                                                                  'complexity in Group Policy or Local '
                                                                  'Security Policy under Account Policies → '
                                                                  'Password Policy, after checking legacy '
                                                                  'system and service account compatibility. '
                                                                  '3. Follow the approved minimum length; do '
                                                                  'not reset existing passwords '
                                                                  'automatically.'),
                                               'rollback': ('若验证发现兼容性影响，由策略负责人恢复已记录的原本地/GPO '
                                                            '值并检查是否有更高优先级域策略覆盖；不要降低其他身份控制。',
                                                            'If validation finds compatibility impact, the '
                                                            'policy owner should restore the recorded '
                                                            'local/GPO value and check whether a '
                                                            'higher-priority domain policy overrides it. Do '
                                                            'not weaken other identity controls.'),
                                               'verification_checkpoint': ('重新导出有效策略并确认期望值；通过组织批准的测试账户验证新密码策略，检查相关身份服务日志。',
                                                                           'Export effective policy again '
                                                                           'and confirm the expected value. '
                                                                           'Test the new-password policy '
                                                                           'with an organization-approved '
                                                                           'test account and review relevant '
                                                                           'identity-service logs.')},
 'WIN_BASELINE_PASSWORD_MINIMUM_LENGTH_LOW': {'title': ('有效密码最小长度低于 Microsoft 指引值',
                                                        'Effective minimum password length is below '
                                                        'Microsoft guidance'),
                                              'description': ('secedit 合并策略显示 MinimumPasswordLength 小于 '
                                                              '8；该比较是维护提示，不代表法规或组织测评结论。',
                                                              'The secedit merged policy reports '
                                                              'MinimumPasswordLength below 8; this is a '
                                                              'maintenance prompt, not a regulatory or '
                                                              'organizational audit conclusion.'),
                                              'impact': ('较短或允许空口令的本地密码更容易被猜测；提高要求也可能增加锁定和兼容支持成本。',
                                                         'Short local passwords or permitted empty passwords '
                                                         'may be easier to guess; stronger requirements can '
                                                         'also increase lockout and compatibility support '
                                                         'costs.'),
                                              'precheck': ('确认有效策略来源、组织密码基线、用户支持能力、服务账户与自动化任务依赖；安排账户锁定恢复流程。',
                                                           'Confirm effective policy origin, the '
                                                           'organizational password baseline, user-support '
                                                           'capacity, service-account and automation '
                                                           'dependencies, and the account-lockout recovery '
                                                           'process.'),
                                              'applicability': ('采用 Microsoft Windows 10/11 指引中的 8 '
                                                                '位参考下限；域细粒度策略可能按账户/组不同，须另行核实。',
                                                                'Uses the 8-character reference minimum in '
                                                                'Microsoft Windows 10/11 guidance. Domain '
                                                                'fine-grained policies can differ by account '
                                                                'or group and must be checked separately.'),
                                              'recommendation': ('1. 与身份负责人核对域、细粒度策略和系统用途。2. 若适用的组织基线要求至少 8 '
                                                                 '位，在策略管理入口提高最小长度；结合口令短语培训并评估服务账户/旧应用影响。3. '
                                                                 '不要把任意数字当作所有环境的合规线。',
                                                                 '1. Review domain and fine-grained policies '
                                                                 'and system use with the identity owner. 2. '
                                                                 'If the applicable organizational baseline '
                                                                 'requires at least 8 characters, raise the '
                                                                 'minimum through policy management; provide '
                                                                 'passphrase guidance and assess service '
                                                                 'account and legacy application impact. 3. '
                                                                 'Do not treat an arbitrary number as a '
                                                                 'universal compliance threshold.'),
                                              'rollback': ('若经批准的变更导致服务账户或业务登录故障，由策略负责人恢复已记录的原值并协调账户凭据轮换；不要写入或共享现有密码。',
                                                           'If an approved change breaks service accounts or '
                                                           'business logons, the policy owner should restore '
                                                           'the recorded value and coordinate credential '
                                                           'rotation. Do not write down or share existing '
                                                           'passwords.'),
                                              'verification_checkpoint': ('重新采集 '
                                                                          'MinimumPasswordLength；用批准的测试账户验证新密码策略和依赖服务，并确认报告未包含口令。',
                                                                          'Recollect MinimumPasswordLength. '
                                                                          'With an approved test account, '
                                                                          'verify the new-password policy '
                                                                          'and dependent services, and '
                                                                          'confirm no passwords appear in '
                                                                          'the report.')},
 'WIN_BASELINE_ACCOUNT_LOCKOUT_DISABLED': {'title': ('有效账户锁定策略未启用阈值',
                                                     'Effective account lockout policy has no threshold'),
                                           'description': ('secedit 合并策略显示 '
                                                           'LockoutBadCount=0；工具不替组织选择锁定阈值或持续时间。',
                                                           'The secedit merged policy reports '
                                                           'LockoutBadCount=0; the tool does not select a '
                                                           'lockout threshold or duration for the '
                                                           'organization.'),
                                           'impact': ('失败登录次数不会按本策略阈值触发锁定响应，可能增加密码猜测机会；阈值设置过低也会造成误锁定和拒绝服务。',
                                                      'Failed logons will not trigger lockout under this '
                                                      'policy threshold, which may increase guessing '
                                                      'opportunities; a threshold set too low can also cause '
                                                      'false lockouts and denial of service.'),
                                           'precheck': ('确认域/GPO '
                                                        '与细粒度密码策略、运维账户和服务账号影响、帮助台解锁能力及监控告警；取得审批的阈值配置。',
                                                        'Confirm domain/GPO and fine-grained password '
                                                        'policies, effects on administrator and service '
                                                        'accounts, help-desk unlock capacity, monitoring '
                                                        'alerts, and the approved threshold settings.'),
                                           'applicability': ('仅反映 secedit '
                                                             '合并策略的系统级阈值；域内个别账户可能应用细粒度策略，不能据此判定所有账户。',
                                                             'Reflects only the system-level threshold in '
                                                             'the merged secedit policy. Individual domain '
                                                             'accounts may use fine-grained policies, so '
                                                             'this does not determine the policy for every '
                                                             'account.'),
                                           'recommendation': ('1. 由身份负责人评估暴露面、服务账户、帮助台解锁能力和域策略。2. '
                                                              '按组织批准的阈值、持续时间及计数器重置时间配置账户锁定策略。3. '
                                                              '先在测试范围验证监控、解锁流程和自动化账户影响。',
                                                              '1. Have the identity owner assess exposure, '
                                                              'service accounts, help desk unlock capacity, '
                                                              'and domain policy. 2. Configure the approved '
                                                              'lockout threshold, duration, and counter '
                                                              'reset period. 3. Validate monitoring, unlock '
                                                              'procedures, and automated account impact in a '
                                                              'test scope first.'),
                                           'rollback': ('若出现业务账号误锁或自动化中断，身份负责人按原记录恢复批准的阈值并执行解锁/凭据核验；不要在未审批情况下无限放宽阈值。',
                                                        'If business accounts are locked unexpectedly or '
                                                        'automation is interrupted, the identity owner '
                                                        'should restore the recorded approved threshold and '
                                                        'perform unlock/credential checks. Do not relax '
                                                        'thresholds indefinitely without approval.'),
                                           'verification_checkpoint': ('重新读取有效 '
                                                                       'LockoutBadCount，并在批准的测试账户上验证锁定、持续时间、计数重置和解锁告警。',
                                                                       'Read effective LockoutBadCount '
                                                                       'again. With an approved test '
                                                                       'account, verify lockout, duration, '
                                                                       'counter-reset behavior, and unlock '
                                                                       'alerts.')},
 'GENERIC_WILDCARD_LISTENER_REVIEW': {'title': ('未被专属规则覆盖的通配地址监听需要人工确认',
                                                'Manually review wildcard listener without a specific rule'),
                                      'applicability': ('仅限已采集监听输出；系统、版本及防火墙语义待确认',
                                                        'Applies only to collected listener output. Confirm '
                                                        'the system, software version, and firewall '
                                                        'semantics.'),
                                      'impact': ('其他专属候选规则未覆盖的通配监听，仍需结合防火墙、路由和业务依赖确认；监听本身不能证明网络可达。',
                                                 'A wildcard listener not covered by a specific candidate '
                                                 'rule requires review with firewall, routing, and business '
                                                 'dependencies; listening alone does not prove network '
                                                 'reachability.'),
                                      'recommendation': ('确认监听进程、授权访问范围、防火墙规则及业务依赖，再按该软件精确版本评估收敛范围。',
                                                         'Confirm the listening process, authorized access '
                                                         'scope, firewall rules, and business dependencies. '
                                                         'Then assess a narrower scope for the exact '
                                                         'software version.'),
                                      'rollback': ('任何获批的配置变更前备份原配置；若连接或业务检查失败，恢复备份并复核。',
                                                   'Back up the original configuration before any approved '
                                                   'change. If connection or business checks fail, restore '
                                                   'the backup and review the result.'),
                                      'verification_checkpoint': ('复采监听与防火墙事实，并由业务负责人确认客户端访问。',
                                                                  'Recollect listener and firewall evidence, '
                                                                  'and have the business owner confirm '
                                                                  'client access.')},
 'REDIS_WILDCARD_BIND_REVIEW': {'title': ('Redis 配置存在通配 bind 值',
                                          'Redis configuration uses a wildcard bind value'),
                                'applicability': ('配置线索；Redis 精确版本、ACL/认证能力、防火墙和业务访问范围均需现场确认',
                                                  'This is a configuration clue. Confirm the exact Redis '
                                                  'version, ACL and authentication capabilities, firewall '
                                                  'rules, and business access scope on site.'),
                                'impact': ('监听范围可能超过业务所需；配置值本身不能证明网络可达。',
                                           'The listening scope may exceed business needs; the configuration '
                                           'value alone does not prove network reachability.'),
                                'recommendation': ('在维护窗口核对客户端来源、防火墙和版本能力，审批后仅保留业务所需绑定地址；不套用其他版本的 ACL 命令。',
                                                   'During a maintenance window, review client sources, '
                                                   'firewall controls, and version capabilities. After '
                                                   'approval, keep only required bind addresses; do not '
                                                   'apply ACL commands from other versions.'),
                                'rollback': ('保留原配置副本；业务连接验证失败时恢复原配置并按既定维护流程复核。',
                                             'Keep a copy of the original configuration. If business '
                                             'connection tests fail, restore it and review under the '
                                             'established maintenance procedure.'),
                                'verification_checkpoint': ('复采配置与监听、防火墙，并验证授权客户端连接。',
                                                            'Recollect configuration, listener, and firewall '
                                                            'evidence, then verify connections from '
                                                            'authorized clients.')},
 'MYSQL_WILDCARD_BIND_REVIEW': {'title': ('MySQL 配置存在通配 bind-address',
                                          'MySQL configuration uses a wildcard bind address'),
                                'applicability': ('配置线索；MySQL 完整版本、TLS、防火墙和业务访问范围需确认',
                                                  'This is a configuration clue. Confirm the full MySQL '
                                                  'version, TLS configuration, firewall rules, and business '
                                                  'access scope.'),
                                'impact': ('服务可能接受超出业务所需网络范围的连接请求；不等同已暴露或可登录。',
                                           'The service may accept connection requests beyond business '
                                           'needs; this does not establish exposure or successful login.'),
                                'recommendation': ('先核对连接来源与防火墙，审批后配置所需监听范围；不得仅凭此证据修改生产数据库。',
                                                   'Review connection sources and firewall controls first. '
                                                   'After approval, configure the required listening scope; '
                                                   'do not modify a production database based only on this '
                                                   'evidence.'),
                                'rollback': ('备份原配置；连接验证失败时恢复原配置并验证应用连接。',
                                             'Back up the original configuration. If connection tests fail, '
                                             'restore it and verify the application connection.'),
                                'verification_checkpoint': ('复采配置与监听，使用获批测试账户验证客户端连通性。',
                                                            'Recollect configuration and listener evidence, '
                                                            'and use an approved test account to verify '
                                                            'client connectivity.')},
 'NGINX_LEGACY_TLS_CONFIG_REVIEW': {'title': ('Nginx 配置包含旧 TLS 协议标识',
                                              'Nginx configuration includes a legacy TLS protocol marker'),
                                    'applicability': ('仅对被导出的单个配置文件匹配；include 未展开，Nginx/OpenSSL 版本及客户端兼容性未确认',
                                                      'The match covers only the exported configuration '
                                                      'file; include directives were not expanded. '
                                                      'Nginx/OpenSSL versions and client compatibility '
                                                      'remain unverified.'),
                                    'impact': ('旧协议可能不符合当前组织策略；实际可协商协议仍需端到端验证。',
                                               'Legacy protocols may not meet current policy; the protocols '
                                               'actually negotiated require end-to-end verification.'),
                                    'recommendation': ('核对完整 include 链、Nginx/OpenSSL 构建与客户端要求，审批后制定兼容升级方案。',
                                                       'Review the full include chain, Nginx/OpenSSL build, '
                                                       'and client requirements; after approval, plan a '
                                                       'compatible upgrade.'),
                                    'rollback': ('保存完整原配置；健康检查或旧客户端验证失败时恢复备份。',
                                                 'Save the complete original configuration. Restore the '
                                                 'backup if health checks or legacy-client tests fail.'),
                                    'verification_checkpoint': ('复采所有相关配置并经批准的 TLS 测试确认协商结果。',
                                                                'Recollect all relevant configuration and '
                                                                'use an approved TLS test to confirm the '
                                                                'negotiated result.')},
 'TOMCAT_CONNECTOR_TLS_DISABLED_REVIEW': {'title': ('Tomcat Connector 显式关闭 TLS',
                                                    'Tomcat Connector explicitly disables TLS'),
                                          'applicability': ('仅匹配 server.xml 显式属性；TLS 也可能由可信反向代理终止，需确认部署拓扑与 '
                                                            'Tomcat 精确版本',
                                                            'Matches only an explicit server.xml attribute. '
                                                            'TLS may terminate at a trusted reverse proxy; '
                                                            'confirm the deployment topology and exact '
                                                            'Tomcat version.'),
                                          'impact': ('此单项配置不能证明业务流量明文传输或外部可达。',
                                                     'This single configuration does not prove that business '
                                                     'traffic is unencrypted or externally reachable.'),
                                          'recommendation': ('核对反向代理到 Tomcat 的传输保护、Connector '
                                                             '绑定范围和业务拓扑，再决定是否调整。',
                                                             'Review transport protection from the reverse '
                                                             'proxy to Tomcat, Connector bind scope, and '
                                                             'business topology before deciding on a '
                                                             'change.'),
                                          'rollback': ('配置变更前备份原 server.xml；应用启动或健康检查失败时恢复并验证。',
                                                       'Back up the original server.xml before changing it. '
                                                       'Restore it and verify if the application fails to '
                                                       'start or fails health checks.'),
                                          'verification_checkpoint': ('复采完整 Connector 配置并在授权环境验证代理链路和健康检查。',
                                                                      'Recollect the complete Connector '
                                                                      'configuration and verify the proxy '
                                                                      'chain and health checks in an '
                                                                      'authorized environment.')},
 'WAS_SECURITY_DISABLED_REVIEW': {'title': ('WebSphere 配置显式关闭安全设置',
                                            'WebSphere configuration explicitly disables a security setting'),
                                  'applicability': ('仅限白名单 XML 字段；WebSphere 完整版本、cell/profile 上下文和配置语义待确认',
                                                    'Limited to allowlisted XML fields. Confirm the full '
                                                    'WebSphere version, cell/profile context, and '
                                                    'configuration semantics.'),
                                  'impact': ('该配置线索可能影响管理或传输安全；单个 XML 片段不能确定生效配置。',
                                             'This configuration clue may affect management or transport '
                                             'security; a single XML fragment does not establish the '
                                             'effective configuration.'),
                                  'recommendation': ('由 WebSphere 管理员确认生效 '
                                                     'cell/profile、同步状态和安全策略，再制定维护窗口内的人工整改。',
                                                     'Have the WebSphere administrator confirm the effective '
                                                     'cell/profile, synchronization state, and security '
                                                     'policy before planning manual remediation during a '
                                                     'maintenance window.'),
                                  'rollback': ('保存对应 profile 原始配置副本；同步或服务启动异常时按厂商流程恢复并复核。',
                                               'Save the original configuration for the relevant profile. If '
                                               'synchronization or service startup fails, restore and review '
                                               'it using the vendor procedure.'),
                                  'verification_checkpoint': ('复采准确 profile/cell 证据，并由管理员验证生效策略和业务连接。',
                                                              'Recollect evidence for the exact '
                                                              'profile/cell, and have an administrator '
                                                              'verify the effective policy and business '
                                                              'connections.')},
 'ORACLE_VALID_NODE_CHECK_DISABLED_REVIEW': {'title': ('Oracle Listener 配置关闭节点来源限制',
                                                       'Oracle Listener configuration disables valid-node '
                                                       'source checks'),
                                             'applicability': ('仅为 listener.ora/sqlnet.ora 白名单配置线索；Oracle '
                                                               '9/10 完整版本、补丁与实际监听器配置待核实',
                                                               'This is an allowlisted '
                                                               'listener.ora/sqlnet.ora configuration clue. '
                                                               'Verify the full Oracle 9/10 version, '
                                                               'patches, and effective listener '
                                                               'configuration.'),
                                             'impact': ('如果单位依赖此控制进行来源限制，配置可能不符合策略；防火墙及其他控制尚未检查。',
                                                        'If the organization relies on this control to '
                                                        'restrict sources, the configuration may not meet '
                                                        'policy; firewalls and other controls have not been '
                                                        'checked.'),
                                             'recommendation': ('核对数据库团队批准的网络访问模型及准确版本文档；不得仅凭该文件直接重启 '
                                                                'Listener 或改动生产配置。',
                                                                "Review the database team's approved network "
                                                                'access model and documentation for the '
                                                                'exact version; do not restart the Listener '
                                                                'or change production configuration based '
                                                                'only on this file.'),
                                             'rollback': ('保留原配置；经批准的变更后连接测试失败则恢复并按 DBA 流程验证。',
                                                          'Keep the original configuration. If connection '
                                                          'tests fail after an approved change, restore it '
                                                          'and verify using the DBA procedure.'),
                                             'verification_checkpoint': ('复采配置与 Listener 状态，并由 DBA '
                                                                         '通过授权测试连接验证策略。',
                                                                         'Recollect configuration and '
                                                                         'Listener status; have the DBA '
                                                                         'verify the policy using an '
                                                                         'authorized test connection.')}}
