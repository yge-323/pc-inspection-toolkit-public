# PC 巡检证据分析报告

- 分析状态：**PARTIAL**
- 资产代号：synthetic\-windows\-01
- 证据包：0b979937\-3954\-450b\-ae00\-734e6c571f15
- 目标：windows / 合成 Windows 演示环境 / synthetic\-1 / x64 / offline bilingual report example / basic

证据均视为不可信输入。SHA-256 只能检查封装后的字节是否变化，不能证明来源真实性。

## 平台支持状态

- 状态：版本覆盖未知，需人工核实
- 资料来源：未匹配到准确版本来源

## 硬件与采集摘要

- **硬件:** CPU=合成样例处理器：仅用于双语报告保真验证; 内存字节=8589934592; 显卡=合成演示图形设备; 磁盘摘要=Drive=C:;FileSystem=NTFS;SizeBytes=107374182400;FreeBytes=5368709120;FreePercent=5
- **系统安全事实:** 采集UID=0
- **Windows安全配置:** RDP拒绝连接标志=0; RDP要求NLA=0; SMB1显式配置=1; 自动登录标志=1; 内置Guest启用=True; 最小密码长度=6; 密码复杂度=0; 账户锁定阈值=0; 密码策略读取状态=UNKNOWN; 防火墙配置文件=PublicProfile;Enabled=0;DefaultInboundAction=0
- **磁盘容量与剩余空间:** 卷数=1; 卷剩余空间=C:：5\.0 GB 可用 / 100\.0 GB 总量（5\.0%）
- **进程与服务:** 进程采集记录数=0; 内存占用靠前进程=未确认; 服务采集记录数=1

## 证据覆盖

| 项目 | 状态 | 退出码 | 说明 |
|---|---|---:|---|
| accounts\.txt | collected | 0 | 采集器仅返回部分事实；请查看采集说明，缺失字段不能视为检查通过。 |
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
| startup\_items\.txt | collected | 0 | 采集器仅返回部分事实；请查看采集说明，缺失字段不能视为检查通过。 |

## 风险发现与整改

### 操作系统生命周期覆盖未确认
- 描述：操作系统生命周期覆盖不受支持，或采集到的操作系统身份未识别。
- 编号：OS\_LIFECYCLE\_COVERAGE\_GAP
- 等级：Warning \(警告\)
- 等级说明：需要人工确认，但不一定代表高风险。
- 证据：\{"source": "", "observed\_product": "", "observed\_version": ""\}
- 整改前核查：实施前核对影响范围、维护窗口与备份
- 适用条件：无法依据当前采集事实确认受支持或已结束支持；这不是安全通过结论。
- 影响与条件：生命周期覆盖未知时，不能据此推断仍受支持或无风险。
- 整改步骤：从可信采集结果核实操作系统产品与版本，并补充经审核的生命周期策略记录后重新分析。
- 回滚：本发现不执行变更。
- 复查：复核 OS 采集来源、产品和版本，并确认策略快照覆盖该身份。
- 资料来源：

### 已启用远程桌面但未要求网络级别身份验证
- 描述：采集到 RDP 已启用且 NLA 未启用；此项不判断防火墙是否允许入站或外部网络是否可达。
- 编号：WIN\_BASELINE\_RDP\_NLA\_DISABLED
- 等级：Attention \(重点关注\)
- 等级说明：需要优先复核，因为可能影响安全、可用性或巡检结论。
- 证据：\{"rdp\_enabled": true, "nla\_required": false, "network\_reachability\_checked": false\}
- 整改前核查：确认服务器角色、获批维护窗口、RDP 客户端版本、远程账户范围及可用的带外/本地回滚通道；记录当前有效策略和防火墙来源。
- 适用条件：来自当前注册表策略事实；不证明 RDP 服务可达。域组策略和操作系统版本可能影响有效配置。
- 影响与条件：启用 RDP 会提供远程登录入口；关闭 NLA 会降低会话建立前的身份验证保护。旧客户端兼容性和业务依赖可能影响处置方式。
- 整改步骤：1\. 若业务不需要 RDP，在确认带外/本地管理通道和依赖后关闭远程桌面。2\. 若业务需要 RDP，按组织策略启用 NLA，并确认所有运维客户端兼容。3\. 复核允许的远程账户和防火墙来源范围；不要把本 Finding 当作网络可达性测试。
- 回滚：若批准的旧客户端暂不兼容，由策略负责人恢复已记录的原 NLA 设置，并保留现有管理会话和带外通道；不得为回滚扩大防火墙范围。
- 复查：重新读取有效 RDP/NLA 策略；从获批客户端建立新会话并确认账户授权与防火墙来源限制。
- 资料来源：https://learn\.microsoft\.com/en\-us/windows\-server/remote/remote\-desktop\-services/remotepc/remote\-desktop\-allow\-access

### 检测到 SMB 1\.0 显式启用
- 描述：LanmanServer SMB1 注册表设置明确为启用；缺失该值不会被当作关闭或开启。
- 编号：WIN\_BASELINE\_SMB1\_ENABLED
- 等级：Attention \(重点关注\)
- 等级说明：需要优先复核，因为可能影响安全、可用性或巡检结论。
- 证据：\{"smb1\_enabled": true, "evidence\_source": "explicit setting"\}
- 整改前核查：确认客户端和服务端 SMBv2/SMBv3 能力、NAS/备份/扫描设备兼容性、共享业务窗口及恢复介质；记录当前 SMB1 功能状态。
- 适用条件：仅当采集到 SMB1 明确启用时触发。不同 Windows 版本的检测和移除入口不同，缺失注册表值保持未知。
- 影响与条件：SMBv1 是旧协议，启用可能增加文件共享攻击面；移除前必须核实旧设备、应用和备份依赖。
- 整改步骤：1\. 盘点 NAS、旧 Windows、扫描/备份设备和应用的 SMB 方言依赖。2\. 在目标系统版本对应的 Windows Features/Server Manager 中按 Microsoft 指南移除或禁用 SMBv1；执行前确认变更窗口和重启要求。3\. 不要仅为消除此项直接改写注册表。
- 回滚：如获批变更导致兼容故障，使用该 Windows 版本支持的功能管理入口恢复原组件状态并按提示重启；之后重新核验依赖，不复制未经批准的注册表模板。
- 复查：用该版本支持的 SMB 配置查询确认 SMB1 状态，并用获批客户端验证必要的共享读写和审计日志。
- 资料来源：https://learn\.microsoft\.com/windows\-server/storage/file\-server/troubleshoot/detect\-enable\-and\-disable\-smbv1\-v2\-v3

### Windows 自动登录已启用
- 描述：Winlogon AutoAdminLogon 标志为 1；采集器不读取或导出自动登录凭据。
- 编号：WIN\_BASELINE\_AUTOLOGON\_ENABLED
- 等级：Attention \(重点关注\)
- 等级说明：需要优先复核，因为可能影响安全、可用性或巡检结论。
- 证据：\{"auto\_logon\_enabled": true, "credential\_value\_read": false\}
- 整改前核查：确认无人值守用途、设备物理访问控制、服务账户权限和凭据保管责任；先识别 GPO/自动登录工具的配置来源。
- 适用条件：只根据 AutoAdminLogon 标志判断；不读取 DefaultPassword、LSA Secret 或其他凭据，也不证明凭据存储位置。
- 影响与条件：自动登录可能让能接触设备的人直接进入配置账户的桌面及其可访问资源。
- 整改步骤：1\. 确认该设备是否确需无人值守登录及其物理/机房访问控制。2\. 若无明确业务授权，由账户/凭据负责人通过组织批准的自动登录管理方式关闭，并轮换可能用于自动登录的凭据。3\. 不要把密码复制到工单、命令行或巡检报告。
- 回滚：如获批服务确需自动登录，由凭据负责人按批准流程恢复原工具/策略并轮换凭据；不要在报告或脚本中恢复明文密码。
- 复查：重新检查自动登录标志和有效策略；确认普通重启后不再自动进入桌面，凭据未出现在采集文件或报告中。
- 资料来源：https://learn\.microsoft\.com/en\-us/troubleshoot/windows\-server/user\-profiles\-and\-logon/turn\-on\-automatic\-logon

### 内置 Guest 账户已启用
- 描述：本地账户摘要中 SID 末尾为 \-501 的内置 Guest 账户处于启用状态；不会导出账户名或 SID。
- 编号：WIN\_BASELINE\_GUEST\_ENABLED
- 等级：Warning \(警告\)
- 等级说明：需要人工确认，但不一定代表高风险。
- 证据：\{"built\_in\_guest\_enabled": true, "account\_name\_exported": false\}
- 整改前核查：确认是否使用 Guest Only 的本地共享安全模型、旧应用或设备集成；检查共享权限、例外审批和回滚管理员账户。
- 适用条件：仅适用于能识别本地内置 Guest SID 的系统；域策略可能控制该状态，账户查询失败时不下结论。
- 影响与条件：访客账户可能扩大本地或共享访问面；Guest Only 共享模型等旧配置也可能依赖它。
- 整改步骤：1\. 核对 Guest 账户是否被共享、服务或旧版本地账户模式依赖。2\. 若无批准用途，在本地用户管理或组织安全策略中禁用内置 Guest。3\. 复核 SMB 共享权限和访问日志，确认没有将 Guest 当作业务账户使用。
- 回滚：如业务验证证明有依赖，由策略负责人恢复已记录的 Guest 状态并重新限制其资源权限；避免恢复默认共享访问。
- 复查：重新采集 Guest 状态；检查相关共享/登录测试和安全日志，确认获批管理账户仍可维护设备。
- 资料来源：https://learn\.microsoft\.com/en\-us/windows/client\-management/mdm/policy\-csp\-localpoliciessecurityoptions

### 至少一个 Windows 防火墙配置文件已关闭
- 描述：至少一个 Domain、Private/Standard 或 Public 防火墙配置文件的显式 EnableFirewall 值为 0。
- 编号：WIN\_BASELINE\_FIREWALL\_PROFILE\_DISABLED
- 等级：Attention \(重点关注\)
- 等级说明：需要优先复核，因为可能影响安全、可用性或巡检结论。
- 证据：\{"disabled\_profiles": \["PublicProfile"\]\}
- 整改前核查：记录关闭的配置文件、当前网络类型、有效 GPO、防火墙例外、远程管理通道和业务监听端口；安排可恢复的维护窗口。
- 适用条件：基于本机配置文件注册表事实；域策略或安全产品可能提供其他过滤层，本结果不做网络可达性验证。
- 影响与条件：关闭中的配置文件可能缺少对应入站/出站规则保护；本项不推断其他配置文件状态或网络边界设备控制。
- 整改步骤：1\. 确认当前网络配置文件、管理入口和已批准的入站例外。2\. 由防火墙策略负责人检查组策略及业务例外；无批准例外时在 Windows Defender 防火墙高级安全管理中恢复对应配置文件。3\. 先验证运维通道和关键业务连接，不要一键重置全部规则。
- 回滚：若恢复配置文件中断获批业务，由防火墙管理员恢复已记录的原 GPO/配置文件与例外，并验证管理通道；不要全局关闭防火墙作为回退。
- 复查：重新读取三个配置文件的有效状态，并分别验证授权管理入口、必要业务流量和规则日志。
- 资料来源：https://learn\.microsoft\.com/en\-us/powershell/module/netsecurity/get\-netfirewallprofile?view=windowsserver2025\-ps

### 有效密码策略未启用复杂性要求
- 描述：secedit 合并策略显示 PasswordComplexity=0；仅评估当前导出的系统策略，不审计账户口令本身。
- 编号：WIN\_BASELINE\_PASSWORD\_COMPLEXITY\_DISABLED
- 等级：Warning \(警告\)
- 等级说明：需要人工确认，但不一定代表高风险。
- 证据：\{"password\_complexity": 0\}
- 整改前核查：确认域加入状态、有效 GPO、细粒度密码策略、服务账户与用户支持影响；记录当前策略来源和批准基线。
- 适用条件：secedit 合并导出中的系统级值；AD DS 细粒度密码策略可按账户/组不同，不能由本字段完整覆盖。
- 影响与条件：新设密码可能不受 Windows 复杂性规则约束，容易采用较弱模式；组织可有经批准的其他认证控制。
- 整改步骤：1\. 与身份/域策略负责人确认本机、域 GPO 和细粒度密码策略的实际适用范围。2\. 若组织基线要求，在组策略或本地安全策略的“账户策略 → 密码策略”中启用复杂性要求，并先验证旧系统/服务账户兼容性。3\. 结合组织批准的最小长度要求，不自动重置现有密码。
- 回滚：若验证发现兼容性影响，由策略负责人恢复已记录的原本地/GPO 值并检查是否有更高优先级域策略覆盖；不要降低其他身份控制。
- 复查：重新导出有效策略并确认期望值；通过组织批准的测试账户验证新密码策略，检查相关身份服务日志。
- 资料来源：https://learn\.microsoft\.com/en\-us/previous\-versions/windows/it\-pro/windows\-10/security/threat\-protection/security\-policy\-settings/password\-must\-meet\-complexity\-requirements

### 有效密码最小长度低于 Microsoft 指引值
- 描述：secedit 合并策略显示 MinimumPasswordLength 小于 8；该比较是维护提示，不代表法规或组织测评结论。
- 编号：WIN\_BASELINE\_PASSWORD\_MINIMUM\_LENGTH\_LOW
- 等级：Warning \(警告\)
- 等级说明：需要人工确认，但不一定代表高风险。
- 证据：\{"minimum\_password\_length": 6, "reference\_floor": 8\}
- 整改前核查：确认有效策略来源、组织密码基线、用户支持能力、服务账户与自动化任务依赖；安排账户锁定恢复流程。
- 适用条件：采用 Microsoft Windows 10/11 指引中的 8 位参考下限；域细粒度策略可能按账户/组不同，须另行核实。
- 影响与条件：较短或允许空口令的本地密码更容易被猜测；提高要求也可能增加锁定和兼容支持成本。
- 整改步骤：1\. 与身份负责人核对域、细粒度策略和系统用途。2\. 若适用的组织基线要求至少 8 位，在策略管理入口提高最小长度；结合口令短语培训并评估服务账户/旧应用影响。3\. 不要把任意数字当作所有环境的合规线。
- 回滚：若经批准的变更导致服务账户或业务登录故障，由策略负责人恢复已记录的原值并协调账户凭据轮换；不要写入或共享现有密码。
- 复查：重新采集 MinimumPasswordLength；用批准的测试账户验证新密码策略和依赖服务，并确认报告未包含口令。
- 资料来源：https://learn\.microsoft\.com/en\-us/previous\-versions/windows/it\-pro/windows\-10/security/threat\-protection/security\-policy\-settings/minimum\-password\-length

### 有效账户锁定策略未启用阈值
- 描述：secedit 合并策略显示 LockoutBadCount=0；工具不替组织选择锁定阈值或持续时间。
- 编号：WIN\_BASELINE\_ACCOUNT\_LOCKOUT\_DISABLED
- 等级：Warning \(警告\)
- 等级说明：需要人工确认，但不一定代表高风险。
- 证据：\{"lockout\_threshold": 0\}
- 整改前核查：确认域/GPO 与细粒度密码策略、运维账户和服务账号影响、帮助台解锁能力及监控告警；取得审批的阈值配置。
- 适用条件：仅反映 secedit 合并策略的系统级阈值；域内个别账户可能应用细粒度策略，不能据此判定所有账户。
- 影响与条件：失败登录次数不会按本策略阈值触发锁定响应，可能增加密码猜测机会；阈值设置过低也会造成误锁定和拒绝服务。
- 整改步骤：1\. 由身份负责人评估暴露面、服务账户、帮助台解锁能力和域策略。2\. 按组织批准的阈值、持续时间及计数器重置时间配置账户锁定策略。3\. 先在测试范围验证监控、解锁流程和自动化账户影响。
- 回滚：若出现业务账号误锁或自动化中断，身份负责人按原记录恢复批准的阈值并执行解锁/凭据核验；不要在未审批情况下无限放宽阈值。
- 复查：重新读取有效 LockoutBadCount，并在批准的测试账户上验证锁定、持续时间、计数重置和解锁告警。
- 资料来源：https://learn\.microsoft\.com/en\-us/previous\-versions/windows/it\-pro/windows\-10/security/threat\-protection/security\-policy\-settings/account\-lockout\-policy

### 可疑自启动服务路径
- 描述：自动启动服务的二进制路径包含配置的高关注路径片段。
- 编号：WIN\_SERVICE\_SUSPICIOUS\_PATH
- 等级：Attention \(重点关注\)
- 等级说明：需要优先复核，因为可能影响安全、可用性或巡检结论。
- 证据：\{"services": \["合成演示服务"\], "matched\_count": 1\}
- 整改前核查：核对服务业务所有者、服务账户、启动方式、签名、文件来源和变更窗口；先确认是否由软件更新器或组织管理代理托管。
- 适用条件：只检查自动启动服务的可执行文件路径是否包含有限高关注路径片段；路径未知时不推断安全或恶意。
- 影响与条件：用户目录或临时目录中的自启动服务需要高度关注。
- 整改步骤：复核服务路径、签名、创建时间和业务来源。
- 回滚：本工具不停止或修改服务；获批变更失败时，由服务负责人按记录恢复原服务配置和文件版本并验证依赖。
- 复查：重新采集服务名称、启动方式和脱敏路径；核对签名/来源，并验证服务及依赖业务恢复正常。
- 资料来源：

### 磁盘剩余空间偏低
- 描述：检测到磁盘或卷剩余空间偏低，可能影响系统更新、日志写入、应用运行或故障排查留存能力。
- 编号：WIN\_DISK\_LOW\_SPACE:C:
- 等级：Warning \(警告\)
- 等级说明：需要人工确认，但不一定代表高风险。
- 证据：\{"source": "disks", "drive": "C:", "volume": null, "mount\_point": null, "device\_id": null, "free\_gb": 5\.0, "total\_gb": 100\.0, "free\_percent": 5\.0, "threshold": \{"free\_percent\_lte": 10\.0, "free\_gb\_lte": 10\.0\}\}
- 整改前核查：确认盘符、文件系统、总容量、可用容量和采集时间；核对日志、数据库、备份及应用目录归属，确认保留策略和业务维护窗口。
- 适用条件：阈值来自当前生效的 Windows 风险规则；虚拟盘、配额卷、精简置备卷及短时波动需结合平台实际解释。
- 影响与条件：剩余空间过低可能导致系统更新失败、应用写日志失败、数据库或中间件异常、排障证据丢失，严重时可能影响服务稳定性。
- 整改步骤：请人工确认受影响卷是否为系统盘或应用日志盘，并结合剩余空间百分比和绝对剩余容量评估；必要时清理无用文件、迁移日志或备份、扩容磁盘或调整保留策略。不要在未确认业务用途前自动删除文件。
- 回滚：本工具不删除文件或扩容磁盘。清理或迁移前记录原路径、容量和保留策略；仅恢复已移动文件或回退经审批的保留策略变更。
- 复查：重新采集同一卷的总容量、可用容量与百分比；检查相关服务、日志写入和备份任务，并确认空间不再快速下降。
- 资料来源：

## 证据缺口

分析不完整；缺失证据不代表未发现风险。
- 证据文件仅部分采集: accounts\.txt \[EVIDENCE\_PARTIAL:accounts\.txt\]
- 证据文件仅部分采集: startup\_items\.txt \[EVIDENCE\_PARTIAL:startup\_items\.txt\]
- 管理员组成员数量未知 \[WINDOWS\_ADMINISTRATOR\_COUNT\_UNKNOWN\]
- 启动项记录数量未知 \[WINDOWS\_STARTUP\_RECORD\_COUNT\_UNKNOWN\]
- 启动项事实缺失或未知 \[WINDOWS\_STARTUP\_FACTS\_MISSING\_OR\_UNKNOWN\]
- 操作系统生命周期覆盖不受支持或身份未识别

## AI辅助建议（非正式结论）

- 状态：AI\_NOT\_RUN
- AI文本与确定性发现分开；不会改变分析状态或风险等级。
- 原因：本地 AI 为可选功能，且本次未请求。
