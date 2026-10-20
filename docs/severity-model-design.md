# Severity 风险等级模型

## 统一目标

项目需要在 analyzer、Markdown report、HTML report、规则文件和文档中使用同一套 severity 口径，避免同一条风险在不同位置被写成 `HIGH`、`Medium`、`Warning` 或 `Need Admin` 后产生理解偏差。

统一 severity 后：

- analyzer 负责生成标准 Finding 和标准 severity。
- report 只负责展示、排序和计数。
- docs 和 rules 使用同一套术语描述风险。
- 旧字段可以继续兼容，但不再作为新输出主口径。

## 标准 Severity 列表

| Severity | 含义 |
|---|---|
| Critical | 明确高风险问题。可能存在严重安全暴露、关键配置风险、明显异常行为，需要优先人工处理。 |
| Attention | 需要重点关注。不一定是立即高危，但存在明显暴露面、配置风险或需要确认的异常。 |
| Warning | 一般警告。有可疑线索或偏离常规，但不能直接判断为高危。 |
| Need Admin | 权限不足导致无法完整确认，需要管理员权限复跑或人工确认。 |
| Info | 信息提示，用于一般说明、未知等级 fallback、无明显风险但值得记录的状态。 |
| OK | 明确正常或通过。 |
| Skipped | 检查被跳过，常见原因包括平台不支持、权限不足但不构成错误、功能不存在。 |
| Failed | 检查执行失败，表示采集或分析失败，需要在报告中可见。 |

## 关键边界

分析完成状态与 Finding severity 是两套不同维度：

- `AnalysisResult.status = OK`：配置和分析完整。
- `AnalysisResult.status = PARTIAL`：采集证据可保留，但配置或分析不完整，必须返回非零并在报告醒目标注。
- `AnalysisResult.status = FAILED`：无法形成有效核心分析状态。

不得用 `0 findings` 替代 `AnalysisResult.status = OK`。local profile 注释必须保留 `base_severity`，不得降低 Critical、配置失败或采集失败。

- `Need Admin` 不等于 `Critical`。它只说明当前权限不足，不能完整确认状态。
- `Failed` 不等于安全高危。它表示检查执行失败或解析失败，需要可见和复核。
- 未识别 severity 不应阻断报告生成；当前 Markdown report 会归入 `Info`。

## 旧等级兼容

旧字段或旧输出中可能仍存在 `HIGH`、`MEDIUM`、`LOW`。

兼容规则：

| Legacy | 标准 severity |
|---|---|
| HIGH / High / high | Critical |
| MEDIUM / Medium / medium | Attention |
| LOW / Low / low | Warning |

兼容只用于读取旧字段或旧测试数据。新增 analyzer Finding、规则和文档主口径必须使用标准 severity，不应继续输出 `HIGH`、`MEDIUM`、`LOW`。

## 职责边界

### Collector

- 只采集事实和状态。
- 不判断风险等级。
- 不自动修复、不修改系统设置。
- 采集失败时记录状态、错误和权限限制。

### Analyzer

- 读取 collector 输出和规则。
- 生成标准 Finding。
- 新 Finding 必须使用标准 severity。
- 可保留 `level` 等旧字段作为兼容输出，但值应与标准 `severity` 保持一致。

### Report

- 只展示、排序和计数。
- Markdown report 首页/总览按标准 severity 固定计数。
- Report 不应新增风险规则，也不应改变 collector 原始输出结构。

## 新增规则要求

后续新增 `rules/*.json` 规则或 analyzer 逻辑时：

- 必须从标准 severity 列表中选择等级。
- `Need Admin` 只能用于权限不足导致无法确认的场景。
- `Failed` 只能用于检查执行失败或解析失败的可见状态。
- 不得把 `Need Admin`、`Skipped`、`Failed` 自动等同为安全高危。
- 不得在新规则中使用 `HIGH`、`MEDIUM`、`LOW` 作为主等级。
