# BeetleShield Backend — Dashboard Overview (Sub-project 8) Design

## 背景与目标

前端 `Dashboard.tsx`(侧边栏"总览",登录后默认落地页)目前整页是 mock 数据:4 个统计卡片(今日加固任务数/成功率/平均耗时/队列中任务,均带"较昨日"环比)、24 小时任务趋势折线图、今日结果分布饼图、最近加固任务表、风险应用 Top5、系统状态卡片(加固引擎/任务队列/工作节点 3-3 在线/引擎版本)。

目标:后端提供一个聚合接口,前端替换全部 mock 数据为真实数据,行为参照刚完成的 report-scoring(单一只读聚合接口、无新表、复用已有服务)。

参考 [`docs/superpowers/specs/2026-07-03-backend-report-scoring-design.md`](2026-07-03-backend-report-scoring-design.md) 中已确立的模式(打分逻辑单一来源、报告为读时计算的纯函数)。

## 范围

**包含:**
- 新增 `GET /api/v1/hardening-tasks/overview` 聚合接口,返回今日统计 + 24 小时趋势 + 今日结果分布 + 最近 7 条任务(全局)+ 风险应用 Top5 + 简化后的系统状态。
- `App.RiskLevel` 首次被写入:加固任务完成时,由 worker 计算并持久化。
- 抽出 `service.ResolveRiskLevel`,供 `BuildHardeningReport`(报告)与 worker(持久化)共用同一套打分→等级映射,避免逻辑分叉。
- 前端 `Dashboard.tsx` 全量接入真实数据,移除所有 mock 数据块。

**不包含(明确排除):**
- 4 个统计卡片的"较昨日"环比趋势 — 直接去掉,不做同比查询。
- 风险应用 Top5 的精确数值分数与风险项数 — 改用 `RiskLevel` 四档到展示分数的固定映射(`critical=90 / high=65 / medium=40 / low=15`),不新增 `App` 表字段。
- "工作节点 3/3 在线"这类多机 worker 集群展示 — 后端只有单进程轮询 worker,无集群状态,直接从系统状态区块删除这张卡片。
- 历史多天趋势对比、自定义时间范围筛选 — 仅"今日"范围,与 report-scoring 保持同样的克制范围原则。

## 后端设计

### 数据模型

`App.RiskLevel *model.RiskLevel` 字段已存在(sub-project 1 引入,`internal/model/app.go:39`),此前从未被写入。本次子项目起,加固任务完成时写入该字段。**不需要新的 migration**,只是行为变化。**不回填历史数据**:在本次改动上线前已经完成加固的存量应用,`RiskLevel` 保持 `NULL`,直到它们下一次加固任务完成才会被写入;风险 Top5 查询天然会跳过 `NULL`,不会报错也不会显示错误等级。

### 打分逻辑抽取:`ResolveRiskLevel`

`internal/service/hardening_report.go` 中现有的 `riskLevelForScore(afterScore int) model.RiskLevel` 与打分计算(`afterScore` 由 `EffectiveFlags` + `DexLevel` 算出)保持不变,新增一个导出的组合函数:

```go
// ResolveRiskLevel computes the risk level for a completed task's strategy,
// the same computation BuildHardeningReport uses internally. Exported so the
// worker can persist App.RiskLevel at completion time without duplicating
// (and risking drift from) the report's scoring logic.
func ResolveRiskLevel(strategy model.Strategy) model.RiskLevel {
	flags := ResolveEffectiveFlags(strategy)
	afterScore := computeAfterScore(flags, strategy.DexLevel) // 从 BuildHardeningReport 中抽出的私有辅助函数
	return riskLevelForScore(afterScore)
}
```

`BuildHardeningReport` 内联的打分求和逻辑抽成 `computeAfterScore(flags EffectiveFlags, dexLevel model.DexObfuscationLevel) int` 私有函数,`BuildHardeningReport` 和 `ResolveRiskLevel` 都调用它,保证两处结果永远一致。

### Repository 改动

`HardeningRepository.CompleteTaskForApp` 签名新增 `riskLevel model.RiskLevel` 参数:

```go
func (r *HardeningRepository) CompleteTaskForApp(taskID uint, unsignedKey string, unsignedSize int64, unsignedSHA string, signedKey string, signedSize int64, signedSHA string, finishedAt time.Time, riskLevel model.RiskLevel) error
```

`transitionTaskForApp` / `transitionTaskForAppTx` 的第五个参数从单一 `appStatus model.AppStatus` 改为 `appUpdates map[string]interface{}`(调用方自行构造 `{"status": ..., "risk_level": ...}` 或 `{"status": ...}`),两处调用点(`CompleteTaskForApp` 传 status+risk_level,`FailTaskForApp` 只传 status)相应更新。这样风险等级和状态在同一事务、同一次 `UPDATE apps` 里落地,不引入额外的数据库往返。

`internal/worker/hardening_worker.go` 在调用 `CompleteTaskForApp` 前,追加一行:

```go
riskLevel := service.ResolveRiskLevel(task.StrategySnapshot)
```

并将其传入 `CompleteTaskForApp` 调用。`FailTaskForApp` 不涉及风险等级——失败任务没有产出加固包,沿用 App 上一次的 `RiskLevel`(如果之前有过成功加固)或保持 `NULL`(从未成功过)。

### 新增查询方法

`HardeningRepository`(`internal/repository/hardening_repository.go`):

- `CountByStatusToday() (map[model.HardeningTaskStatus]int64, error)` — 按 `created_at` 落在今日(服务器本地时间,`time.Now()` 当天 00:00 起)的任务,按 `status` 分组计数。用于"今日加固任务数"(全部状态之和)与"今日结果分布"饼图(success/failed/processing,其中 processing = queued + running 之和)。
- `HourlyCountsToday() ([24]int64, error)` — 今日任务按 `created_at` 小时分桶计数,下标 0-23 对应 00 时-23 时。
- `AverageCompletedDurationToday() (avgSeconds float64, ok bool, err error)` — 今日 `status = completed` 且 `started_at`/`finished_at` 均非空的任务,`AVG(EXTRACT(EPOCH FROM finished_at - started_at))`;`ok=false` 表示今日无已完成任务,调用方展示为 0。
- `QueueCount() (int64, error)` — 全量(不限定"今日")`status IN (queued, running)` 计数,反映当前实际排队情况。
- `Recent(limit int) ([]model.HardeningTask, error)` — 全局(不按 `AppID` 过滤)按 `created_at DESC` 取最近 N 条,`Preload("App")`。区别于已有的 `RecentByApp(appID uint, limit int)`。

`AppRepository`(`internal/repository/app_repository.go`):

- `TopByRiskLevel(limit int) ([]model.App, error)` — `WHERE risk_level IS NOT NULL`,按严重程度降序(`CASE risk_level WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END DESC`),同级按 `updated_at DESC`,`LIMIT limit`。

### `DashboardService`

新文件 `internal/service/dashboard_service.go`,风格类比 `hardening_report.go`(纯聚合,不新增状态):

```go
type HourlyPoint struct {
	Hour  string `json:"hour"`  // "00:00".."23:00"
	Count int    `json:"count"`
}

type ResultDistribution struct {
	Success    int `json:"success"`
	Failed     int `json:"failed"`
	Processing int `json:"processing"` // queued + running
}

type DashboardTaskItem struct {
	TaskID      uint                       `json:"taskId"`
	TaskNo      string                     `json:"taskNo"`
	AppName     string                     `json:"appName"`
	PackageName string                     `json:"packageName"`
	Version     string                     `json:"version"`
	Status      model.HardeningTaskStatus  `json:"status"`
	DurationSeconds *int                   `json:"durationSeconds"` // nil：尚未完成
	CreatedAt   time.Time                  `json:"createdAt"`
}

type DashboardRiskApp struct {
	AppID       uint            `json:"appId"`
	Name        string          `json:"name"`
	PackageName string          `json:"packageName"`
	RiskLevel   model.RiskLevel `json:"riskLevel"`
	DisplayScore int            `json:"displayScore"` // 固定映射：critical=90/high=65/medium=40/low=15
}

type DashboardSystemStatus struct {
	EngineVersion string `json:"engineVersion"`
	QueueCount    int    `json:"queueCount"`
}

type DashboardOverview struct {
	TodayTaskCount     int                 `json:"todayTaskCount"`
	SuccessRate        float64             `json:"successRate"`       // 0-100，今日 completed/(completed+failed)*100，无分母时为 0
	AvgDurationSeconds int                 `json:"avgDurationSeconds"`
	QueueCount         int                 `json:"queueCount"`
	HourlyTrend        []HourlyPoint       `json:"hourlyTrend"`       // 固定 24 项
	ResultDistribution ResultDistribution  `json:"resultDistribution"`
	RecentTasks        []DashboardTaskItem `json:"recentTasks"`       // 最多 7 条
	RiskTop5           []DashboardRiskApp  `json:"riskTop5"`          // 最多 5 条
	SystemStatus       DashboardSystemStatus `json:"systemStatus"`
}
```

`DashboardService.GetOverview() (*DashboardOverview, error)` 依次调用上述 repository 方法拼装结果;`SuccessRate` 计算时分母为 0(今日无 completed/failed 任务)则返回 `0`,不做除零,结果保留原始 `float64`(前端负责 `toFixed(1)` 展示)。`AvgDurationSeconds` 由 repository 返回的 `float64` 四舍五入取整(`math.Round`)后赋值,`ok=false` 时直接置 `0`。`engineVersion` 复用 report-scoring 已经线好的 `cfg.HardeningEngineVersion`(`DashboardService` 构造时注入,与 `HardeningService` 相同的字段来源)。

### 接口

`GET /api/v1/hardening-tasks/overview`,`middleware.JWTAuth` 权限(不加 `RequireRole`,三种角色均可访问,与 `GET /:id`、`GET /:id/report` 一致)。

**路由顺序注意**:必须注册在 `hardeningTasks.GET("/:id", ...)` **之前**,否则 `overview` 会被 Gin 当作 `:id` 参数值匹配到 `Get` handler,导致 404(参数解析失败)而不是命中新路由。

```go
hardeningTasks.GET("/overview", deps.HardeningHandler.GetOverview)
hardeningTasks.GET("/:id", deps.HardeningHandler.Get)
```

Handler 直接返回 `response.Success`,无特殊错误分支(聚合查询本身不会因为"任务不存在"这类业务状态失败)。

### 配置

`DashboardService` 复用已有 `cfg.HardeningEngineVersion`,`main.go` 装配时传入,不新增配置项。

## 前端设计

### 新增文件

- `src/api/types.ts`:追加 `HourlyPoint`、`ResultDistribution`、`DashboardTaskItem`、`DashboardRiskApp`、`DashboardSystemStatus`、`DashboardOverview` 接口定义,字段与后端一一对应。
- `src/api/dashboard.ts`:`getDashboardOverview(): Promise<DashboardOverview>`,写法参照 `hardening.ts`。

### `Dashboard.tsx` 改动

- 删除文件顶部 `Mock 数据` 整块(`hourlyData`/`pieData`/`recentTasks`/`riskApps` 及其类型定义)。
- 组件内新增 `overview`/`loading`/`error` state,`useEffect` 挂载时调用 `getDashboardOverview()`;"刷新"按钮的 `onClick` 从"仅 bump `refreshKey`"改为"重新调用接口"。
- `MetricCard` 组件签名去掉 `trend`/`trendDir`/`trendText`,渲染上去掉环比徽标(对应 JSX 里的 `metric-trend` 区块整体删除)。四个卡片改绑定 `overview.todayTaskCount`、`overview.successRate.toFixed(1) + '%'`、格式化后的 `overview.avgDurationSeconds`(复用类似 `${min}分${sec}秒` 的格式化)、`overview.queueCount`。
- `lineConfig.data` 改为 `overview?.hourlyTrend ?? []`;`pieConfig.data` 改为由 `overview.resultDistribution` 展开成 `[{type:'成功',value},...]`;`pieConfig.statistic.content.content` 改为 `String(overview?.todayTaskCount ?? 0)`。
- 任务表格 `dataSource` 改为 `overview?.recentTasks ?? []` 映射出的行(`status` 需要把后端 `HardeningTaskStatus`(`queued/running/completed/failed`)映射到现有 `TaskRecord['status']`(`success/error/processing/pending`):`completed→success`、`failed→error`、`running→processing`、`queued→pending`);`duration` 列在 `durationSeconds` 为 `null` 时展示"进行中..."或"等待中"(依据 status),否则格式化为"X分Y秒"。
- 风险 Top5 区块改用 `overview?.riskTop5 ?? []`,`app.risk` 用后端下发的 `displayScore`,`app.level` 用 `riskLevel` 直接映射(`riskLevelConfig` 已有 `high/medium/low` 三档,`critical` 需要补一个映射项或归并到 `high` 展示色——沿用 `high` 的红色即可,不新增视觉档位)。
- 系统状态区块从 4 张卡片精简为 3 张:`加固引擎`(固定 `status="online"`, value 固定"运行中")、`任务队列`(`overview.systemStatus.queueCount` 个任务)、`引擎版本`(`overview.systemStatus.engineVersion`),删除"工作节点"卡片及其数据。
- 顶部日期文案(目前硬编码"2026年7月2日")改为 `new Date().toLocaleDateString()` 之类的动态当前日期,或保持静态但去掉"今日数据实时更新"里对不存在的实时刷新的暗示——具体取"动态生成当日日期"这一种处理,不做成可配置项。
- `loading` 时整页 `Spin`;`overview` 为空/接口异常时 `Empty`,参照 `Reports.tsx` 已有模式。

## 测试计划

**后端:**
- `internal/repository/hardening_repository_test.go`:新增 `TestHardeningRepository_CountByStatusToday`、`TestHardeningRepository_HourlyCountsToday`、`TestHardeningRepository_AverageCompletedDurationToday`、`TestHardeningRepository_QueueCount`、`TestHardeningRepository_Recent`,复用现有 `runID` 前缀隔离手法避免共享库脏数据干扰。
- `internal/repository/app_repository_test.go`:新增 `TestAppRepository_TopByRiskLevel`。
- `internal/service/hardening_command_test.go` 或 `hardening_report_test.go`:新增 `TestResolveRiskLevel` 系列用例(全开/全关/单项),断言与 `BuildHardeningReport(...).RiskLevel` 结果一致。
- `internal/service/dashboard_service_test.go`(新建):用固定 fixture 断言聚合结果的字段计算正确(成功率分母为 0 时返回 0、`durationSeconds` 为 nil 的未完成任务等边界)。
- `internal/worker/hardening_worker_test.go`:补充/更新用例断言 `CompleteTaskForApp` 收到的 `riskLevel` 参数与 `StrategySnapshot` 匹配,且 `App.RiskLevel` 落库正确。
- `internal/handler/hardening_handler_test.go`:新增 `TestHardeningHandler_GetOverview`,并确认路由顺序(`/overview` 不被 `/:id` 吞掉)。
- 全量 `go vet ./... && gofmt -l .` + `go test ./...`。

**前端:**
- `npx tsc --noEmit`。
- 浏览器手动验证:(1)有已完成任务且有风险数据时,4 卡片/折线图/饼图/任务表/Top5/系统状态均显示真实数据;(2)全新空库(无任何任务)时不崩溃,呈现合理空状态。

## 已知限制(明确记录,不在本次范围内)

- 成功率、平均耗时等指标仅统计"今日"(服务器本地时区的自然日),不支持自定义时间范围。
- 风险 Top5 分数为四档固定映射展示值,不是连续精确分数;两个应用同为同一档时排序仅按 `updated_at` 区分,不代表其中一个"风险更高"。
- 加固引擎在线状态为进程存活的隐含判断,没有做进一步的深层健康检查(例如 dpt.jar 是否可执行)。
