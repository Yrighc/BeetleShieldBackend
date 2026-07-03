# BeetleShield 后端 - 子项目七：加固报告（风险评分对比）

日期：2026-07-03

## 背景与范围

子项目一~六（基础设施+应用管理、用户管理+RBAC、策略中心、加固流水线、审计日志、失败审计扩展+独立 API 请求日志）均已完成并合入 `main`。原始路线图（`docs/superpowers/specs/2026-07-02-backend-foundation-app-management-design.md` 的"后续子项目"）里还剩两项未做：加固报告、Dashboard 聚合接口。二者中，Dashboard 的"风险应用 Top5"依赖加固报告定义的评分体系，因此先做本子项目。

前端 `Reports.tsx`（`BeetleShieldFrontend/src/pages/Reports.tsx`）目前整页是 mock 数据，包含四块：
1. 加固前/加固后风险指数（0-100 圆形进度，越低越安全）+ 一句话风险等级描述
2. 5 个防护维度的加固前后强度对比（反调试保护、DEX 混淆、SO 加壳保护、资源文件加密、签名校验，柱状图，越高越好）
3. 检测防护项清单表格（危害级别/状态已修复或已保留/描述）
4. 加固交付凭证（输出文件名、SHA-256、引擎版本、下载/PDF 导出按钮）

**关键前提**：`dpt.jar` 加固过程本身不产出任何评分或检测报告数据（已确认——`internal/worker/engine.go` 只逐行采集 stdout/stderr 分类日志级别，没有结构化输出）。`dpt-shell` 仓库里的 `test_defense.py` 是需要真实设备 + frida 的动态对抗评估脚本，是完全独立的离线安全研究工具，与本流水线无关，不在考虑范围内。

**结论：风险评分是后端基于 `HardeningTask.StrategySnapshot` 的规则打分，不是真实测量值。**

**本子项目范围**：
1. 评分算法：一套确定性的 `Strategy → 风险指数/维度强度/检测清单` 规则函数。
2. 新增只读接口 `GET /api/v1/hardening-tasks/:id/report`，实时计算，不落库。
3. `internal/service/hardening_command.go` 抽取 `EffectiveFlags` 小函数，供 `BuildDPTCommand` 与报告评分器共用同一套"这个 Strategy 字段是否真的转成了 dpt.jar 参数"的判断逻辑。
4. 新增配置项 `HARDENING_ENGINE_VERSION`，作为报告"引擎版本"字段的来源。
5. 前端：`Reports.tsx` 改接真实接口。

**明确不在本子项目范围内**：
- 加固前 APK 真实静态扫描（评估已有保护现状）——工作量等同一个独立子项目，且当前上传流程没有相关基础设施，属于过度设计。加固前基线统一按固定值处理（见下）。
- PDF 导出——后端只提供数据接口；前端可用浏览器打印或后续单独做，本子项目不实现。
- 跨多次加固任务的评分趋势对比——前端当前设计只展示单次任务的前后对比，不需要历史序列。
- SSL Pinning 检测——策略模型里没有对应字段，报告里如实展示为"未启用"，不假装支持。

## 已知的现有代码问题（会影响评分准确性，本子项目一并处理）

排查 `hardening_command.go` 的 `BuildDPTCommand` 发现两处 Strategy 字段是"装饰性"的，从未真正转成 dpt.jar 参数：

- `Strategy.Debugger`：模型里存在、策略中心 CRUD 也读写它，但 `BuildDPTCommand` 里完全没有引用它对应的 dpt.jar 参数。
- `Strategy.SoShell` 为 `aes`/`custom_so` 时：`BuildDPTCommand` 里只有 `SoShell == vmp`（且需要和 `DexLevel == high` 一起走 `--enable-vmp`）才会加参数，`aes`/`custom_so` 两个取值目前不产生任何独立的 dpt.jar 参数。

这两个字段是否要接入真实引擎参数，是加固流水线子项目的遗留问题，**不在本子项目里修**（改 `BuildDPTCommand` 的参数生成逻辑有风险，且不是本子项目目标）。但报告评分绝不能直接读这些"没有实际效果"的字段——否则会出现"用户勾选了但报告说已防护，引擎实际没执行"的数据造假。处理方式：评分只认 `EffectiveFlags`（见下），`Debugger`/`SoShell==aes|custom_so` 不参与任何加分判定。

## 架构方案：不落库，实时计算

`GET /api/v1/hardening-tasks/:id/report` 从已有数据现算现出：
- 输入：`HardeningTask.StrategySnapshot`（评分用）+ `UnsignedSHA256`/`SignedTestSHA256`/ObjectKey（交付凭证用）+ 关联的 `App.Name`/`PackageName`/`Version`。
- 不新建表。评分是纯函数 `Strategy → Report`，属于可派生数据，落库是重复存储；不落库还意味着评分公式以后调整时，历史任务的报告会自动用新公式重算，不会被写死的旧分数卡住导致新旧任务报告口径不一致。
- 只有 `status == completed` 的任务能查看报告；非 `completed`（`queued`/`running`/`failed`）返回业务错误码，提示"加固任务未完成，无法生成报告"，与现有状态机保持一致（`failed` 任务没有产物，自然也没有意义生成"加固后"报告）。

权限：与现有 `GET /api/v1/hardening-tasks/:id` 详情接口一致，只挂 `JWTAuth`，任意已登录角色（`admin`/`developer`/`auditor`）可查看。

## 评分算法

### `EffectiveFlags`：单一真值来源

新增 `internal/service/hardening_command.go`：

```go
type EffectiveFlags struct {
	EmulatorDetect bool
	RootDetect     bool
	HookDetect     bool // AntiHook || Frida || Xposed
	SigVerify      bool
	StringEncrypt  bool
	AssetsEncrypt  bool
	VMPEnabled     bool // DexLevel==high || SoShell==vmp
}

func ResolveEffectiveFlags(s model.Strategy) EffectiveFlags {
	return EffectiveFlags{
		EmulatorDetect: s.Emulator,
		RootDetect:     s.RootDetect,
		HookDetect:     s.AntiHook || s.Frida || s.Xposed,
		SigVerify:      s.Signature,
		StringEncrypt:  s.StringEncrypt,
		AssetsEncrypt:  s.ResEncrypt,
		VMPEnabled:     s.DexLevel == model.DexLevelHigh || s.SoShell == model.SoShellVMP,
	}
}
```

`BuildDPTCommand` 改为先调用 `ResolveEffectiveFlags`，再根据返回的布尔值拼参数（替换掉现有的 9 个内联 `if input.Strategy.XXX` 判断，行为完全不变，只是判断逻辑挪到了一个可复用、可单测的函数里）。报告评分器（新文件 `internal/service/hardening_report.go`）同样调用 `ResolveEffectiveFlags`，保证两处判断永远不会漂移。

### 总体风险指数（0-100，越低越安全）

- 加固前固定 **100 分**：未加固 = 完全暴露，这是对任何 APK 都成立的客观陈述，不依赖具体策略、不做静态扫描。
- 加固后 = `100 - Σ(已生效维度权重)`，最低クランプ在 5 分（不允许出现 0 分"绝对安全"的误导性展示）。

维度权重表（合计 100）：

| 维度 | 权重 | 判定（基于 `EffectiveFlags`） |
|---|---|---|
| 反调试/环境检测 | 15 | `EmulatorDetect \|\| RootDetect` → 满分；否则 0 |
| Hook/注入防御 | 15 | `HookDetect` → 满分；否则 0 |
| 签名校验 | 15 | `SigVerify` → 满分；否则 0 |
| DEX 混淆 | 20 | `DexLevel`：`low`→5，`medium`→12，`high`→20 |
| SO 加壳保护 | 20 | `VMPEnabled`→20；`SoShell` 为 `aes`/`custom_so`（未接入引擎，属于前述"已知问题"，不给分）→0；`none`→0 |
| 资源/字符串加密 | 15 | `StringEncrypt` 和 `AssetsEncrypt` 都启用→15；启用其一→8；都未启用→0 |

前端 5 维度柱状图的"加固前"统一展示为 `0%`（未加固 = 该维度强度为零），"加固后"按 `该维度得分 / 权重 * 100` 换算成百分比。

### 检测清单（6 项，对应前端表格）

| 检测项 | 判定 | 危害级别 | 描述（后端硬编码，复用前端现有中文文案） |
|---|---|---|---|
| Frida/Xposed 注入防御 | `HookDetect` | 超危 | 已植入反动态注入探针，自动识别并中断 Hook 调用。/ 未启用 Hook 检测，建议开启反 Hook 策略。 |
| 系统调试器绕过 | `EmulatorDetect` | 高危 | 已启用模拟器与调试环境检测。/ 未启用环境检测，建议开启。（`Debugger` 字段未接入引擎，不参与本项判定，避免虚假"已修复"） |
| DEX 字节码明文暴露 | `DexLevel == high` | 高危 | 已对 DEX 主体数据进行指令虚拟化（VMP）混淆。/ 当前混淆强度为 {low\|medium}，建议提升至 high。 |
| 硬编码明文字符串泄露 | `StringEncrypt` | 中危 | 全局敏感明文采用 AES 加密，运行时动态解密。/ 未启用字符串加密。 |
| 设备 Root 权限滥用 | `RootDetect` | 中危 | 已启用多级 Root 检测。/ 未启用 Root 检测。 |
| SSL Pinning 证书校验 | 恒为 false（策略模型无对应字段） | 低危 | 检测到未配置本地证书单向校验。建议在下次加固策略中启用。 |

状态字段：判定为 `true` → `已修复`，`false` → `已保留`。

### 交付凭证

直接复用 `HardeningTask` 已有字段，不新增计算：
- 输出文件名：从 `SignedTestObjectKey`（优先）或 `UnsignedObjectKey` 取路径最后一段
- 校验哈希：`SignedTestSHA256`（优先）或 `UnsignedSHA256`
- 引擎版本：新增配置项 `HARDENING_ENGINE_VERSION`（`.env`/`.env.example` 新增，`internal/config/config.go` 的 `Config` 结构体新增 `HardeningEngineVersion string` 字段，默认值 `"BeetleShield Engine v2.4.1"`），静态展示，不做真实版本探测（`dpt.jar` 不暴露版本查询接口，YAGNI）。

## API 设计

`GET /api/v1/hardening-tasks/:id/report`

成功响应 `data`：

```json
{
  "taskId": 123,
  "taskNo": "TASK-2406-0156",
  "appName": "钱包 Pro",
  "packageName": "com.wallet.pro",
  "version": "5.2.1",
  "beforeScore": 100,
  "afterScore": 18,
  "riskLevel": "低风险",
  "dimensions": [
    { "name": "反调试保护", "before": 0, "after": 100 },
    { "name": "DEX 混淆", "before": 0, "after": 100 },
    { "name": "SO 加壳保护", "before": 0, "after": 100 },
    { "name": "资源文件加密", "before": 0, "after": 100 },
    { "name": "签名校验", "before": 0, "after": 100 }
  ],
  "checklist": [
    { "name": "Frida/Xposed 注入防御", "level": "超危", "status": "已修复", "desc": "..." }
  ],
  "artifact": {
    "fileName": "com.wallet.pro_protected_signed.apk",
    "sha256": "e3b0c...",
    "engineVersion": "BeetleShield Engine v2.4.1"
  }
}
```

`riskLevel` 按 `afterScore` 区间映射：`<30`→"低风险"，`30-60`→"中风险"，`>60`→"高风险"（与前端 `Dashboard.tsx` 已有的 `riskLevelConfig` 三档保持一致，为子项目八 Dashboard 复用同一套阈值埋下基础）。

错误响应：
- 任务不存在：`404`，复用现有 `ErrHardeningTaskNotFound`
- 任务未完成：新增 `service.ErrHardeningReportNotReady`，`409`，`"加固任务未完成，无法生成报告"`

## 涉及文件

- `internal/service/hardening_command.go`：新增 `ResolveEffectiveFlags`，`BuildDPTCommand` 改为基于它拼参数（行为不变）。
- `internal/service/hardening_report.go`（新增）：评分算法 + `BuildReport(task model.HardeningTask, app model.App) ReportOutput`。
- `internal/service/hardening_service.go`：新增 `GetReport(ctx, taskID) (ReportOutput, error)`，内部查任务+校验状态+调用 `BuildReport`。
- `internal/handler/hardening_handler.go`：新增 `GetReport` handler。
- `internal/router/router.go`：`hardeningTasks.GET("/:id/report", deps.HardeningHandler.GetReport)`。
- `internal/config/config.go` + `.env.example` + `.env`：新增 `HARDENING_ENGINE_VERSION`。
- 前端 `BeetleShieldFrontend/src/pages/Reports.tsx` + 新增 `src/api/hardeningReport.ts`：改接真实接口，`selectedAppId` 改为传 `taskId`（选择应用时先查该应用最近一次 completed 任务）。

## 数据库改动

无。不新增表，不改现有表结构，`Migrate()` 无需改动。

## 测试

延续既有模式（真实本地 Postgres）：
- `internal/service/hardening_command_test.go`：`ResolveEffectiveFlags` 各字段组合的单测；`BuildDPTCommand` 重构后原有测试断言应保持全绿（回归验证）。
- `internal/service/hardening_report_test.go`：`BuildReport` 针对几种典型 Strategy 组合（全开/全关/部分开）验证分数、维度、清单的确定性输出。
- `internal/handler/hardening_handler_test.go`：新增端到端用例——`completed` 任务返回报告；`queued`/`running`/`failed` 任务返回 409；不存在的任务返回 404。
- 前端：手动验证选择不同应用后报告数据随策略变化，非 completed 任务的应用不可选或给出提示。
