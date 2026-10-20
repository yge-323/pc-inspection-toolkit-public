# Windows 安全软件与管家残留检测设计

> Batch 2A 边界：vendor 通用关键词和目录候选由 tracked default registry 提供，collector 与 analyzer 仅接收已校验的 registry 注入，不再各自维护 vendor 策略副本。本机预期进程和机器例外只能进入 ignored local profile。

## 1. 模块定位

本模块用于 Windows 本地只读巡检，识别安全软件、电脑管家、驱动工具、浏览器相关管家组件及其卸载残留线索。

核心用途：

- 巡检安全软件或电脑管家是否仍在安装、运行或自启动。
- 对比卸载前后状态，确认是否仍有服务、驱动、任务、启动项或目录残留。
- 发现多种安全软件或管家类软件同时存在的冲突线索。
- 识别可能影响 Defender、防火墙、网络过滤、文件过滤或系统启动的残留组件。
- 为人工审计提供证据和下一步检查建议。

明确非目标：

- 不自动卸载。
- 不自动删除文件或目录。
- 不自动停止服务。
- 不自动禁用驱动。
- 不自动修改 Defender。
- 不自动修改防火墙。
- 不自动修改浏览器。
- 不自动清理注册表。
- 不做全盘文件关键词扫描。
- 不扫描用户文档、照片、聊天记录或无关隐私数据。
- 不把朋友电脑或个人电脑的机器级路径、白名单写入通用设计。

模块输出必须坚持：检测到相关软件不等于恶意；所有结论都应表达为“线索 + 需人工确认”。

## 2. 推荐命名

候选名称评估：

| 类型 | 名称 | 评价 |
|---|---|---|
| collector | `collectors/security_vendors.py` | 推荐。表达为安全软件厂商/产品检测，不暗示清理。 |
| component | `security_vendors` | 推荐。适合作为 Finding component 和报告内部键。 |
| 设计文档 | `docs/security-vendor-residue-check-design.md` | 推荐。明确包含残留检测设计。 |
| 中文名称 | Windows 安全软件与管家残留检测 | 推荐。用户可读，边界清楚。 |
| collector | `360_removal` | 不推荐。过窄且暗示卸载。 |
| collector | `security_cleanup` | 不推荐。暗示清理和处置。 |
| collector | `malware_removal` | 禁止。误导为恶意软件清除。 |

最终推荐：

- collector：`collectors/security_vendors.py`
- analyzer component：`security_vendors`
- 文档：`docs/security-vendor-residue-check-design.md`
- 中文名称：Windows 安全软件与管家残留检测

## 3. 第一版支持范围

第一版关键词表只作为检测线索，不等同恶意判定。关键词应集中管理，避免散落在 collector 逻辑中。第一版不追求覆盖所有安全软件。

建议结构：

```json
{
  "360": ["360", "Qihoo", "Qihu", "360safe", "360sd", "360se", "360Chrome"],
  "Tencent PC Manager": ["QQPCMgr", "Tencent PC Manager"],
  "Kingsoft": ["Kingsoft", "KSafe"],
  "Huorong": ["Huorong", "火绒"],
  "Ludashi": ["Ludashi", "MasterLu", "鲁大师"],
  "2345": ["2345"],
  "Lenovo PC Manager": ["Lenovo PC Manager", "Lenovo Butler"],
  "Driver Tools": ["DriverGenius", "驱动精灵", "DriverTalent", "驱动人生"]
}
```

设计原则：

- 火绒、腾讯电脑管家、联想电脑管家等正常软件不能直接判为高危。
- `360` 这类短关键词不能在任意数字字段中裸匹配，必须结合来源字段和上下文。
- 厂商关键词后续宜迁移到规则或配置文件，例如 `rules/security_vendor_keywords.example.json`，但第一版可先在 collector 内集中常量管理。

## 4. 采集范围

### 已安装程序

只读检查：

```powershell
HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall*
HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall*
HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall*
```

建议字段：

- `display_name`
- `display_version`
- `publisher`
- `install_location`
- `uninstall_string`
- `quiet_uninstall_string`
- `registry_source`
- `matched_vendor`
- `matched_keyword`

注意：

- 不执行 `UninstallString`。
- `UninstallString` 只作为 evidence。
- 报告中避免完整显示敏感参数；可截断或只展示 executable/path 摘要。

### Windows 服务

现有 `collectors/services.py` 已采集：

- `Name`
- `DisplayName`
- `State`
- `StartMode`
- `StartName`
- `PathName`

安全软件模块建议复用这些字段，映射为：

- `name`
- `display_name`
- `status`
- `start_type`
- `binary_path`
- `matched_vendor`
- `matched_keyword`

### 系统驱动

第一版需要补充当前缺失的驱动视图。建议只读查询系统驱动服务，不做驱动文件扫描。

建议字段：

- `name`
- `display_name`
- `state`
- `start_mode`
- `path_name`
- `service_type`
- `matched_vendor`
- `matched_keyword`

失败处理：

- 权限不足：collector 或子项状态记录 `Need Admin`。
- 命令不可用或平台不支持：记录 `Skipped`。
- 命令失败：记录 `Failed`。
- 不阻塞整体巡检。

### 计划任务

现有 `collectors/scheduled_tasks.py` 已采集：

- `TaskName`
- `TaskPath`
- `State`
- `Author`
- `Actions`

建议复用并映射为：

- `task_name`
- `task_path`
- `state`
- `executable`
- `arguments`
- `matched_vendor`
- `matched_keyword`

`Actions` 可在 analyzer 或轻量 collector 中拆分 executable / arguments；拆分失败时保留摘要即可。

### 启动项

现有 `collectors/startup_items.py` 已覆盖：

- `HKLM Run`
- `HKLM WOW6432Node Run`
- `HKCU Run`
- 当前用户 Startup 文件夹
- 公共 Startup 文件夹

建议复用现有 startup_items collector 数据，不重复采集 Run key 和 Startup folder。安全软件模块只做关键词匹配和聚合。

### 常见目录

第一版只检查明确常见位置是否存在，不递归扫描整个目录，不读取目录内用户文件内容。

建议范围：

- `Program Files`
- `Program Files (x86)`
- `ProgramData`
- 当前用户 `AppData\Local`
- 当前用户 `AppData\Roaming`
- 当前用户 `AppData\LocalLow`

建议字段：

- `path`
- `exists`
- `matched_vendor`
- `matched_keyword`
- `source_type`

重要限制：

- 只检查常见 vendor 目录名是否存在。
- 不遍历用户文档、照片、下载、聊天记录。
- 不做全盘关键词搜索。

### 浏览器相关

第一版建议设计为可选能力。

可选检查：

- 默认浏览器是否为相关厂商浏览器。
- 已安装程序中是否存在 360、2345 等浏览器。
- 常见浏览器扩展目录中是否存在明确厂商目录名。

不做：

- 不解析浏览器历史。
- 不读取 Cookies。
- 不读取账户、Token、密码、收藏夹。
- 不读取浏览器密钥库。
- 不修改主页、搜索引擎或扩展。

### Defender 与防火墙关联状态

第一版只记录关联状态，不修改：

- Defender 是否启用。
- 是否检测到其他杀毒产品注册。
- 防火墙是否启用。
- 是否存在厂商相关防火墙规则。

架构建议：

- 防火墙状态优先复用现有 `firewall` collector。
- Defender 当前没有独立 collector；第一版可暂不实现，或在 Phase 2 单独设计轻量只读 collector。
- security_vendors 不应重复执行已有 firewall 查询。

## 5. 方案对比

### 方案 A：新增 security_vendors collector，自行重复采集所有信息

优点：

- collector 输出完整，单模块自包含。
- analyzer 输入简单。

缺点：

- 重复采集 services、scheduled_tasks、startup_items、firewall。
- 执行时间更长。
- 超时风险更高。
- 与已有 collector 数据可能不一致。
- 测试面更大。
- 不符合当前 MVP 小步复用原则。

### 方案 B：完全复用现有 collectors，由 analyzer 聚合已有结果，只新增 analyzer 逻辑

优点：

- 不新增 collector。
- 执行时间最短。
- 复用现有服务、任务、启动项、防火墙数据。

缺点：

- 当前缺少 installed programs、drivers、directories。
- 无法可靠判断“卸载项不存在但残留存在”。
- analyzer 会承担过多采集缺口推断。
- 残留检测证据不足。

### 方案 C：新增轻量 security_vendors collector，仅采集缺失信息，其他复用现有 collectors

做法：

- 新增 `collectors/security_vendors.py`。
- 该 collector 只采集：
  - installed programs
  - drivers
  - common directories
  - 可选 browser_related
  - 可选 Defender/AV registration 摘要
- analyzer 聚合：
  - `security_vendors`
  - `services`
  - `scheduled_tasks`
  - `startup_items`
  - `firewall`

优点：

- 避免重复采集。
- 补齐残留检测所需关键缺口。
- 执行时间可控。
- 超时风险较低。
- 职责清晰：collector 采集事实，analyzer 聚合判断。
- 测试可以分层：collector mock、analyzer aggregate mock。
- 符合当前 Windows Python MVP 小步演进。

缺点：

- analyzer 需要聚合多个 collector，逻辑略复杂。
- report 需要识别新 collector 的 summary 结构。

明确推荐：**方案 C**。

理由：当前项目已有 services、scheduled_tasks、startup_items、firewall collector，重复采集会增加复杂度和不一致风险；但 installed programs、drivers、directories 是残留判断必需证据，仍需要轻量补齐。方案 C 在可维护性、执行时间、职责边界和 MVP 适配上最平衡。

## 6. 推荐架构

推荐链路：

```text
collectors/security_vendors.py
  -> 采集 installed_programs / drivers / directories / optional browser_related / optional security_status

existing collectors
  -> services / scheduled_tasks / startup_items / firewall

analyzers/risk_analyzer.py
  -> 聚合 security_vendors + services + scheduled_tasks + startup_items + firewall
  -> 生成 security_vendors component Findings

reports/markdown_report.py
  -> 新增“安全软件与电脑管家组件”摘要章节
  -> 标准 Finding 明细复用现有展示
```

职责边界：

- collector：只采集事实，不判断风险，不执行清理。
- analyzer：按 vendor 聚合证据，生成标准 Finding。
- report：只展示摘要、计数和前若干条明细。

## 7. Collector 输出结构

应贴合现有 collector 返回格式：

```json
{
  "collector": "security_vendors",
  "status": "ok",
  "data": {
    "installed_programs": [],
    "drivers": [],
    "directories": [],
    "browser_related": [],
    "security_status": {},
    "summary": {
      "vendors_detected": [],
      "installed_vendor_count": 0,
      "driver_count": 0,
      "directory_count": 0,
      "browser_related_count": 0,
      "service_count": 0,
      "task_count": 0,
      "startup_count": 0,
      "residue_candidate_count": 0
    }
  },
  "errors": []
}
```

说明：

- `service_count`、`task_count`、`startup_count` 可由 analyzer 聚合后填入 Finding evidence；collector 自身可先不填。
- 如果 Phase 2 collector 不聚合现有 collector 数据，则 summary 中相关 count 可省略或为 0。
- 每个子采集失败应记录在 `errors`，并尽量保留其他子项结果。

installed program item：

```json
{
  "display_name": "Example",
  "display_version": "1.0",
  "publisher": "Example Publisher",
  "install_location": "C:\\Program Files\\Example",
  "uninstall_string": "C:\\Program Files\\Example\\uninstall.exe",
  "quiet_uninstall_string": "",
  "registry_source": "HKLM64",
  "matched_vendor": "ExampleVendor",
  "matched_keyword": "Example"
}
```

driver item：

```json
{
  "name": "ExampleDrv",
  "display_name": "Example Driver",
  "state": "Running",
  "start_mode": "System",
  "path_name": "C:\\Windows\\System32\\drivers\\example.sys",
  "service_type": "Kernel Driver",
  "matched_vendor": "ExampleVendor",
  "matched_keyword": "Example"
}
```

directory item：

```json
{
  "path": "C:\\ProgramData\\Example",
  "exists": true,
  "matched_vendor": "ExampleVendor",
  "matched_keyword": "Example",
  "source_type": "ProgramData"
}
```

## 8. Finding 规则设计

### WIN_SECURITY_VENDOR_PRESENT

建议字段：

- `finding_id`: `WIN_SECURITY_VENDOR_PRESENT`
- `title`: 检测到安全软件或电脑管家组件
- `severity`: `Attention`
- `category`: `Security Software`
- `component`: `security_vendors`
- `needs_human_review`: `true`

触发条件：

- 卸载项中存在相关产品。
- 或存在明确运行中的相关服务。

含义：

- 软件存在不等于恶意。
- 需要确认是否用户主动安装。
- 需要确认是否与 Defender 或其他安全软件冲突。
- 不自动建议卸载。

### WIN_SECURITY_VENDOR_RESIDUE

建议字段：

- `finding_id`: `WIN_SECURITY_VENDOR_RESIDUE`
- `title`: 检测到安全软件卸载残留
- `severity`: `Warning`
- `category`: `Security Software`
- `component`: `security_vendors`
- `needs_human_review`: `true`

触发条件建议：

- 同一 vendor 的卸载项不存在。
- 但仍存在相关服务、驱动、计划任务、启动项。
- 目录残留仅作为辅助证据；不应仅凭一个空目录直接生成 Warning。

权重建议：

- 驱动残留：高权重。
- 服务残留：高权重。
- 计划任务 / 启动项残留：中高权重。
- 目录残留：低权重，通常作为 Info 或 evidence。

关联方式：

- analyzer 以 `matched_vendor` 聚合 installed_programs、services、drivers、tasks、startup_items、directories。
- 对每个 vendor 判断 `uninstall_present`。
- 若 `uninstall_present=false` 且高权重残留存在，生成 Residue Finding。

### WIN_SECURITY_VENDOR_DRIVER_REVIEW

建议字段：

- `finding_id`: `WIN_SECURITY_VENDOR_DRIVER_REVIEW`
- `title`: 检测到安全软件相关驱动
- `severity`: `Warning`
- `category`: `Security Software`
- `component`: `security_vendors`
- `needs_human_review`: `true`

触发条件：

- 检测到相关驱动。
- 特别是卸载项不存在但驱动仍存在。

含义：

- 不应自动删除。
- 需要确认签名、状态、启动类型和文件路径。
- 可能影响网络过滤、文件系统、系统启动或安全软件功能。
- 驱动存在不一定异常，也可能是正常在用组件。

## 9. Evidence 设计

Finding evidence 只保留摘要，不塞入完整 raw。

建议字段：

- `vendor`
- `matched_keyword`
- `source_type`
- `name`
- `display_name`
- `path`
- `status`
- `start_type`
- `signed_publisher`
- `uninstall_present`
- `service_present`
- `driver_present`
- `task_present`
- `startup_present`
- `directory_present`
- `related_item_count`

第一版可实现：

- `vendor`
- `matched_keyword`
- `source_type`
- `name`
- `display_name`
- `path`
- `status`
- `start_type`
- `uninstall_present`
- `service_present`
- `driver_present`
- `task_present`
- `startup_present`
- `directory_present`
- `related_item_count`

后续再实现：

- `signed_publisher`
- 更细的 Defender / 第三方 AV 注册状态。
- 浏览器策略或扩展的低隐私风险摘要。

聚合 evidence 示例：

```json
{
  "vendor": "360",
  "matched_keyword": "360safe",
  "uninstall_present": false,
  "service_present": true,
  "driver_present": true,
  "task_present": false,
  "startup_present": false,
  "directory_present": true,
  "related_item_count": 3,
  "items": [
    {
      "source_type": "service",
      "name": "ExampleService",
      "display_name": "Example Service",
      "path": "C:\\Program Files\\Example\\example.exe",
      "status": "Running",
      "start_type": "Auto"
    }
  ]
}
```

## 10. 误报控制

必须遵守：

1. 检测到厂商软件不等于恶意。
2. 火绒等正常安全软件不得判 `Critical`。
3. 正常安装的软件使用 `Attention`。
4. 卸载项不存在但仍有活动服务、驱动、任务或启动项时，才考虑 `Warning`。
5. 仅存在空目录或日志目录时，不应直接判 `Warning`。
6. 多款安全软件同时存在可以提示冲突风险，但第一版不要自动判 `Critical`。
7. 厂商名出现在普通文件名或用户文档中不应命中。
8. 不扫描用户文档内容。
9. 不因为包含 `360` 数字就简单匹配，避免误判端口、版本号、文件大小。
10. 关键词匹配应结合来源字段，例如 `publisher`、`display_name`、`path`、`service name`。

短关键词匹配建议：

- `360` 仅在 installed program display name、publisher、service/display name、明确目录名中匹配。
- 不在纯数字字段、版本号、端口、大小、随机路径片段中匹配。
- 对 path 匹配时优先匹配路径段名称，而非任意子串。

## 11. 超时与失败处理

设计要求：

- 每类采集命令设置合理超时。
- 某一类采集失败不阻断其他采集。
- 权限不足记录 `Need Admin`。
- 不支持记录 `Skipped`。
- 命令失败记录 `Failed` 或 collector `partial`，并写入 `errors`。
- 所有错误写入 `errors`，不抛出导致主流程退出。
- 不递归扫描全盘。
- 不执行可能长时间阻塞的 WMI 全量查询。

建议超时：

| 子项 | 建议超时 |
|---|---:|
| installed programs | 10s |
| drivers | 15s |
| directories exists check | 10s |
| browser related optional | 10s |

目录检查只做有限路径 `Test-Path`，不得 `Get-ChildItem -Recurse`。

## 12. 报告展示设计

Markdown 报告建议新增章节：

```text
## 安全软件与电脑管家组件
```

内容包括：

- 检测到的厂商。
- 安装程序数量。
- 服务数量。
- 驱动数量。
- 计划任务数量。
- 启动项数量。
- 疑似残留数量。
- 需人工复核项。

展示原则：

- 每类最多显示前 10 条。
- 不显示完整 raw。
- 不显示完整卸载命令敏感参数。
- 明确标记“存在不等于恶意”。
- 驱动残留要单独突出。
- 同一 vendor 尽量聚合展示。

Finding 明细继续复用标准 Finding 展示：`title / severity / category / component / description / evidence / impact / recommendation / verification_checkpoint / needs_human_review`。

## 13. 测试方案

建议至少覆盖：

1. 已安装 360 产品
   - 生成 `WIN_SECURITY_VENDOR_PRESENT`。
   - severity 为 `Attention`。

2. 已安装火绒
   - 生成 `WIN_SECURITY_VENDOR_PRESENT`。
   - 不生成 `Critical`。

3. 卸载项不存在，但 360 服务仍存在
   - 生成 `WIN_SECURITY_VENDOR_RESIDUE`。
   - severity 为 `Warning`。

4. 卸载项不存在，但驱动仍存在
   - 生成 `WIN_SECURITY_VENDOR_RESIDUE`。
   - 同时生成 `WIN_SECURITY_VENDOR_DRIVER_REVIEW`。

5. 只存在一个空目录
   - 不生成 `Warning`。
   - 可记录 `Info` 或仅显示 evidence。

6. 正常系统无相关软件
   - 不生成 security vendor Finding。

7. 字段缺失
   - 不报错。

8. 权限不足
   - 返回 `Need Admin` 或相关状态。
   - 不阻断主流程。

9. 多个厂商同时存在
   - 正确聚合。
   - 不重复生成大量相同 Finding。

10. 关键词 `360` 出现在无关数字字段
    - 不误报。

## 14. 真实案例验证

可使用朋友电脑上的 360 卸载前后巡检作为验证案例：

1. 卸载前运行一次。
2. 正常卸载 360。
3. 重启。
4. 卸载后再次运行。
5. 对比安装程序、服务、驱动、任务、启动项、目录。
6. 生成 before / after 对比。

边界：

- 不把朋友电脑具体路径、用户名、白名单写入通用代码。
- 不在工具中自动执行清理。
- 不记录浏览器隐私数据。
- 可使用脱敏 mock 数据补测试。
- vendor directory candidate 只能是受控根目录下的相对目录片段；绝对路径、drive/UNC/rooted 路径、`.`、`..`、混合分隔符逃逸均必须在加载阶段拒绝，并在 Collector 拼接前再次校验。

## 15. 分阶段开发计划

### Phase 1：设计

- 完成本设计文档。
- 明确边界、输出结构、误报控制和测试方案。

### Phase 2：实现最小 collector 或缺失采集能力

- 新增轻量 `collectors/security_vendors.py`。
- 只采集 installed programs、drivers、directories。
- 其他信息复用现有 collectors。

### Phase 3：接入 analyzer Finding

- 聚合 `security_vendors`、`services`、`scheduled_tasks`、`startup_items`、`firewall`。
- 接入三条 Finding。

### Phase 4：接入 Markdown report

- 新增“安全软件与电脑管家组件”摘要章节。
- 每类最多展示前 10 条。

### Phase 5：单元测试与 smoke test

- 添加 collector mock 测试。
- 添加 analyzer mock 测试。
- 添加 Markdown report 展示测试。
- 运行 compileall、相关 tests、smoke test。

### Phase 6：真实电脑卸载前后验证

- 使用脱敏 before / after 结果验证规则是否符合人工预期。
- 不把个人机器路径或白名单写入通用规则。

## 16. 当前结论

推荐采用方案 C：新增轻量 `security_vendors` collector 采集缺失信息，同时复用现有 services、scheduled_tasks、startup_items、firewall collectors，由 analyzer 聚合生成 Finding。

本模块适合进入 Phase 2，但 Phase 2 应先写 mock 测试和输出结构约束，再开发 collector。
