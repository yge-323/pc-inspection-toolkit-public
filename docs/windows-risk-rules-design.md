# Windows 风险规则配置设计

## 1. 规则配置化目标

目标是为后续将 Windows 风险判断逐步迁移到配置文件做准备。

配置化后希望达到：

- 风险规则可审计。
- 规则含义可解释。
- 端口、共享、启动项、磁盘、权限等判断不散落在多个模块里。
- 机器级策略和通用规则分离。
- analyzer 可以统一生成 Finding。
- Markdown / HTML 报告只负责展示 Findings。

Batch 2A 已将默认 registry 接入 analyzer。由于现有 portable spec、build 和 release 工具仍引用兼容文件名，唯一默认权威暂保留为 `rules/windows_risk_rules.example.json`，并通过 `registry_role: default` 明确其职责；不得再创建内容独立漂移的第二份默认规则。

## 当前三层权威

1. Python 保留 Finding、AnalysisResult、severity/status 语义、合并与校验算法、必需 rule ID、Critical 保护和 exact-match 语义。
2. tracked default registry 管理端口、范围、阈值、vendor 通用模式、规则开关、severity、文案和 local override policy。
3. ignored user override 只允许白名单稀疏 patch；ignored local profile 只在通用分析后做精确审计注释，不改写 registry、不删除 Finding。

默认 registry 或 user override 严重错误时不得 fallback：只读采集可保留，风险分析进入 `PARTIAL`。local profile 损坏时通用分析继续，但不应用机器注释，整体状态仍为 `PARTIAL`。

Batch 2A Fix2 已完成剩余运行策略的唯一权威迁移：管理员数量和事件数量阈值位于 `thresholds`；服务、计划任务和启动项匹配数据位于 `path_patterns`；运行 Finding 的开关、severity、标题、影响和建议位于对应 `rules[]`。Python 仅保留字段提取、计数、规范化、匹配算法和 Finding 组装，不提供这些字段的文案或策略 fallback。

启动项链路的职责固定为：Collector 只采集 Registry Run 与 Startup 文件夹事实；Analyzer 使用已校验 registry 生成唯一正式 Finding；Report 的正式风险区只消费 `AnalysisResult.findings`。旧 raw 中可能存在的 Collector 风险字段不参与匹配、Finding 数量、severity 汇总或总体结论。

## 2. 为什么暂不做复杂 DSL

MVP 阶段不做复杂规则 DSL。

原因：

- 复杂 DSL 会增加维护成本。
- 容易让规则变成另一套难调试的程序。
- 当前 collector 数据结构还在稳定中。
- 先把 Finding 模型和规则元数据定下来更重要。

当前策略：

- example JSON 先描述规则意图、证据字段和建议。
- analyzer 后续用普通 Python 小步读取规则。
- 先接入少量低风险规则。
- 等数据结构稳定后再考虑更强的规则表达能力。

## 3. 端口规则不能写死

端口风险不能只按端口号判断。

必须结合：

- 端口号。
- 监听地址。
- 进程名。
- 防火墙状态。
- 当前网络 Profile。
- 用户确认或机器级策略。

错误做法：

- 看到 22 就认为安全。
- 看到 22 就认为高危。
- 看到 7897 就认为安全。
- 看到 445 Listen 就直接 Critical。

当前 Python MVP 的这三条正式网络 Finding 只根据已校验 Registry 端口和监听地址
生成“监听暴露审查”。Analyzer 可以保留采集到的原始进程值作为上下文，但进程名
不是这三条 listener-only 规则的正式触发证据契约；防火墙、共享权限和 RDP 启用
状态也不参与当前结论。

如后续要判断服务身份、SMB 入站可达性或 RDP 实际可用性，必须在独立批次中把
对应 Collector 证据接入 Analyzer，并同时增加缺失、阻断和矛盾证据测试。不得只
修改 Registry 文案，使报告声称已完成尚未实现的复合判断。

## 4. 重点规则设计

### 22 / SSH

规则目标：

- 发现 SSH 远程访问入口。
- 不把 22 写成全局安全。
- 不把当前机器的使用习惯写成通用规则。

当前实现：

- Registry 配置的 SSH 审查端口监听在 `0.0.0.0` 或 `::`：
  `Warning / listener exposure review`。
- Finding 不声称进程已经确认为 `sshd`，也不声称机器策略已确认该监听为预期。

### 445 / SMB

当前实现：

- Registry 配置的 SMB 审查端口监听在 `0.0.0.0` 或 `::`：
  `Attention / listener exposure review`。
- Finding 不声称 SMB-In 已允许，也不声称共享权限宽泛；这些内容只能作为人工
  后续检查项。

### 3389 / RDP

当前实现：

- Registry `ports.rdp` 配置的端口监听在 `0.0.0.0` 或 `::`：
  `Attention / listener exposure review`。
- Finding 不声称远程桌面已启用，也不声称防火墙允许入站。
- `collectors/remote_desktop.py` 的 `DEFAULT_RDP_PORT = 3389` 仅用于采集 Windows
  RDP 协议默认事实；它不参与 Analyzer 的风险端口判断。Analyzer 的可调整风险
  端口唯一来自 Registry。

### 7890-7899 / 本地代理

规则目标：

- 识别代理端口是否只在本机可用。
- 避免把 7890-7899 写成全局安全。

建议：

- 监听地址为 `127.0.0.1` 或 `::1`，且进程为 `clash-verge`、`verge-mihomo`、`mihomo`：`Info / Local proxy`。
- 监听地址为 `0.0.0.0` 或 `::`：`Warning / Proxy exposed`。
- 进程未知：`Warning / Unknown proxy-like port`。

### 共享目录权限

规则目标：

- 发现非默认共享和宽泛权限。
- 避免默认管理共享误报。

建议：

- 默认管理共享不自动判高危。
- 非默认共享需要展示。
- `Everyone`、`Guest`、`Anonymous`、`ANONYMOUS LOGON` 等权限线索：`Warning / Broad share access`。

`WIN_SHARE_BROAD_ACCESS` 当前仅为 future candidate，不属于运行 registry，也不属于 `REQUIRED_RULE_IDS`。在 share Analyzer 分支和对应契约测试同批实现前，不得把它重新加入可配置运行规则。

### 启动项高关注路径

规则目标：

- 发现持久化线索。
- 避免把所有 AppData 启动项都当恶意。

建议：

- 启动项来自 `AppData`、`Temp`、`Downloads`、`Users\Public`、`ProgramData`：`Warning / Startup item review`。
- 启动项使用 `powershell`、`cmd`、`wscript`、`cscript`、`mshta`、`rundll32`、`regsvr32`、`python`：`Warning / Startup item review`。

### 磁盘剩余空间

规则目标：

- 发现系统盘或关键盘空间不足。
- 避免把 USB 小容量盘误判为系统风险。

建议：

- 系统盘剩余低于 10%：`Warning`。
- 系统盘剩余低于 5%：`Attention`。
- 后续应结合系统盘标识、绝对剩余空间和应用日志目录位置。

### BitLocker Need Admin

规则目标：

- 提示权限不足导致 BitLocker 状态不完整。

建议：

- BitLocker 读取失败且疑似权限不足：`Need Admin`。
- `Need Admin` 不等同 `Critical`。
- 正式验机时建议管理员权限复跑。

## 5. 机器级策略说明

机器级策略用于记录用户确认的预期行为。

示例：

- 本机 22/TCP 确认为 SSH 远程访问。
- 某个管理员账户确认为保留账户。
- 某个本地代理端口确认为开发或代理软件使用。

要求：

- 本机白名单不提交。
- example 文件只提供示例。
- 不把用户当前机器习惯写死成通用规则。
- 真实机器策略后续建议放在 `config/inspection_config.json`，并加入 `.gitignore`。

Batch 2A Fix1 的机器级边界：

- local exception 只允许各 rule ID 明确列出的证据字段，禁止 `null`、未知字段和自由表达式；字段必须真实存在且值严格相等。
- expected listener 必须同时提供 port、protocol、process 和非空 addresses；地址采用规范化后的严格集合相等，不采用交集匹配。
- profile ID 只存在于加载后的内存配置对象，不进入 Finding、raw、报告、warning 或 error。
- schema 和整数配置显式拒绝 bool。
- override/profile 不存在与路径异常严格区分；目录、链接或不可读非普通文件不得静默视为未配置。

## 6. 后续接入计划

### 第一步：先生成 Finding

- 在 analyzer 中逐步统一输出 `models.finding.Finding`。
- 先接入少量明确规则。
- 保持现有 smoke test 通过。

### 第二步：让 Markdown 报告展示 Findings

- Markdown 报告优先展示 Finding。
- 每条 Finding 展示 severity、evidence、impact、recommendation。
- 不确定项写“需人工确认”。

### 第三步：最后再考虑 HTML 和脱敏示例

- 等 Markdown 稳定后再接入 HTML。
- 使用脱敏样例数据生成示例报告。
- 不使用本机真实 raw 或本机报告作为公开示例。
