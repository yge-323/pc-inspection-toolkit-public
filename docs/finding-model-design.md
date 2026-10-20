# Finding 数据结构设计

## 1. 为什么需要 Finding

当前 Python MVP 已经开始形成 collector、analyzer、report 分层。随着 Windows collector 增加，风险判断如果散落在 collector 或 report 中，会导致：

- collector 同时承担采集和判断，职责变重。
- report 里混入风险判断，后续 Markdown / HTML 容易重复实现。
- 同一风险在不同报告格式中表达不一致。
- AI Prompt 难以获得结构统一的风险列表。

统一 `Finding` 的目标是：

- 把“风险发现”作为稳定的数据结构。
- 让 analyzer 统一输出 Finding 列表。
- 让 Markdown / HTML 只负责展示 Finding。
- 让后续 AI Prompt 可以直接引用结构化 Finding。

Batch 2A 新增最小 `AnalysisResult`，字段为 `status`、`findings`、`config_evidence`、`warnings` 和 `errors`。调用方不得仅凭 `findings` 为空判断“无风险”，还必须确认分析状态为 `OK`；`PARTIAL` 和 `FAILED` 必须在 raw 与报告中可见。

## 2. collector / analyzer / report 的职责边界

### collector

collector 只采集事实。

例如：

- 端口是否监听。
- 防火墙规则是否启用。
- 启动项命令和路径。
- 磁盘剩余空间。
- BitLocker 状态是否可读取。

collector 不负责：

- 下最终风险结论。
- 判断用户是否应该关闭端口。
- 自动修复。

### analyzer

analyzer 负责把事实转换为 Finding。

例如：

- 445 正在监听且 SMB-In 入站允许，生成 `Attention` Finding。
- 启动项使用脚本解释器，生成 `Warning` Finding。
- BitLocker 普通权限不可读，生成 `Need Admin` Finding。

analyzer 不负责：

- 直接调用系统命令。
- 修改系统设置。
- 渲染 Markdown / HTML。

### report

report 负责展示。

例如：

- 按 severity 排序 Finding。
- 展示证据和建议。
- 控制大列表只展示前 N 条。

report 不负责：

- 采集事实。
- 重新实现风险规则。

## 3. Finding 字段说明

`models/finding.py` 中的 `Finding` 字段：

- `finding_id`：稳定 ID，例如 `WIN_SMB_445_ALLOWED`。
- `title`：面向用户的简短标题。
- `severity`：风险等级，例如 `Info`、`Warning`、`Attention`、`Critical`、`Need Admin`。
- `category`：风险分类，例如 `network_ports`、`shares`、`startup_items`。
- `component`：具体组件，例如 `SMB`、`RDP`、`BitLocker`。
- `description`：发现说明。
- `evidence`：结构化证据，保存端口、路径、规则、账号等关键字段。
- `impact`：可能影响。
- `recommendation`：下一步建议。
- `verification_checkpoint`：人工复核点。
- `needs_human_review`：是否需要人工确认。

## 4. Finding 示例

```python
from models.finding import Finding

finding = Finding(
    finding_id="WIN_PORT_22_REVIEW",
    title="SSH remote access requires confirmation",
    severity="Warning",
    category="network_ports",
    component="SSH",
    description="Port 22/TCP is listening and should be confirmed against machine policy.",
    evidence={
        "local_port": 22,
        "process": "sshd"
    },
    impact="Remote access may be expected or may increase exposure if not intended.",
    recommendation="Confirm whether SSH is expected on this machine.",
    verification_checkpoint="Check user or machine-level expected remote access policy.",
    needs_human_review=True
)
```

## 5. 后续如何用于 Markdown 报告和 AI Prompt

Markdown 报告后续可以这样使用 Finding：

- 先展示 `Critical` / `Attention` / `Warning` / `Need Admin`。
- 每条 Finding 展示标题、等级、证据、影响、建议。
- `OK` 和 `Info` 可以放在后面或摘要中。

AI Prompt 可以直接引用 Finding：

- 把 Finding 列表作为结构化输入。
- 要求 AI 基于证据解释风险。
- 不让 AI 直接猜测没有证据的风险。
- 不确定项统一写“需人工确认”。

## 6. 暂不做复杂规则引擎

MVP 阶段暂不做复杂 DSL 或规则引擎。

暂不做：

- 嵌套条件表达式语言。
- 用户自定义 Python 表达式。
- 动态执行规则代码。
- 复杂优先级和冲突解决系统。

先做：

- 统一 Finding 数据结构。
- 设计 example JSON。
- 小步把 analyzer 中的确定规则迁移为 Finding 输出。
- 保持规则可解释、可审计、容易调试。

## 7. AnalysisResult 完整性边界

- `AnalysisResult.status` 必须由配置状态、Collector 完整性和 Analyzer 执行结果共同决定。
- 任一影响分析完整性的 `partial`、`failed` 或 `need_admin` Collector 会使整体至少为 `PARTIAL`；没有可用采集时为 `FAILED`。
- Analyzer 异常只记录稳定异常类型，不把异常消息中的本机值写入 raw 或报告，并保留已经完成的 Collector 结果。
- `AnalysisResult` 禁止隐式布尔判断；调用方必须显式检查 `.status` 或 `.findings`。
- local profile 注释不得包含 profile ID 或匹配值，只保留匹配类型、字段名、disposition 和 base severity。

## 8. 当前运行 Finding ID 映射

Finding ID 不从标题生成；当前可配置运行 Finding 的 `finding_id` 与 registry rule ID 严格相同。

| Finding ID / Registry Rule ID | Analyzer 分支 |
|---|---|
| `WIN_PORT_22_REVIEW` | network / SSH |
| `WIN_SMB_445_ALLOWED` | network / SMB |
| `WIN_RDP_EXPOSED_REVIEW` | network / RDP |
| `WIN_PROXY_PORT_EXPOSED` | network / proxy |
| `WIN_ADMINISTRATOR_COUNT_REVIEW` | users / administrator count |
| `WIN_SERVICE_SUSPICIOUS_PATH` | services / path pattern |
| `WIN_SCHEDULED_TASK_SUSPICIOUS_PATH` | scheduled tasks / path pattern |
| `WIN_BITLOCKER_NEED_ADMIN` | disks / BitLocker evidence completeness |
| `WIN_DISK_LOW_SPACE` | disks / free-space threshold |
| `WIN_STARTUP_SUSPICIOUS_PATH` | startup items / registry-backed patterns |
| `WIN_SECURITY_VENDOR_PRESENT` | security vendor / installed or active |
| `WIN_SECURITY_VENDOR_RESIDUE` | security vendor / residue |
| `WIN_SECURITY_VENDOR_DRIVER_REVIEW` | security vendor / driver |
| `WIN_EVENT_LOG_ERROR_VOLUME` | event logs / critical or error count |

`WIN_PORT_22_REVIEW`、`WIN_SMB_445_ALLOWED` 和 `WIN_RDP_EXPOSED_REVIEW`
保留现有 ID 作为 legacy-compatible identifier。当前 Python MVP 的这三个 Finding
只表示 Registry 配置端口在所有接口上监听；其 description、impact 和 recommendation
不得声称已经验证进程身份、防火墙 Allow、共享权限或 RDP 启用状态。

Local Profile 对非字符串 evidence 执行严格类型和值匹配：
`type(actual) is type(expected)` 后才比较值，因此 `True` 不得匹配 `1`，
`False` 不得匹配 `0`。Local Profile 仍只能添加审计注释，不能删除 Finding 或
降低基础 severity。

Loader 要求以上 ID 完整存在，并拒绝重复 ID、未知运行 ID、字段不完整或 enabled 但无 Analyzer 执行入口的规则。`WIN_SHARE_BROAD_ACCESS` 是 future candidate，当前不在运行映射中。
