# BeetleShield 后端 - 子项目四：加固流水线

日期：2026-07-02

## 背景与范围

BeetleShield 是 Android 应用加固管理平台。当前后端已经具备登录鉴权、用户管理、应用管理和策略中心能力。应用管理负责上传 APK/AAB 原始文件并保存到 MinIO；策略中心保存全局生效策略；前端已有“应用管理”和“加固流水线”页面，目前仍使用 mock 数据展示任务详情、六步流程、日志和历史列表。

本子项目实现后端加固流水线：用户从已有应用发起加固任务，后端异步调用本地 dpt 加固引擎 jar，记录任务步骤、日志和产物，并向前端提供轮询查询与下载接口。

加固引擎位置：

```text
/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar
```

引擎源码项目：

```text
/Users/yrighc/work/hzyz/project/test/dpt-shell
```

本子项目范围：

1. 加固任务、步骤、日志和产物元数据建模。
2. 后端进程内串行 worker，按队列顺序一次执行一个加固任务。
3. dpt.jar 本地命令行适配器。
4. 策略快照、VMP 规则快照和高强度默认参数映射。
5. 加固任务列表、详情、日志、产物下载、应用加固历史接口。
6. 任务失败处理和服务重启恢复。

明确不在本子项目范围内：

- 多 worker 并发、分布式队列、Redis/RabbitMQ 等外部队列。
- 任务取消、任务重试、重新执行接口。
- 策略模板管理重做。流水线只保存执行时策略展示名和策略快照；项目/客户产品模板管理留给后续策略中心增强。
- 真实加固报告和风险评分对比。报告模块后续基于本任务数据继续设计。
- 日志审计页面的完整 API。流水线日志只覆盖加固任务执行日志。

## 设计决策

采用“后端进程内串行 worker + dpt.jar 本地命令适配器”。

原因：

- dpt 引擎当前是本地 jar 包，最自然的集成方式是后端下载原始包到本地工作目录后执行命令。
- APK/AAB 加固耗时不可控，不适合 HTTP 同步阻塞。
- 第一版只需要单机串行执行，避免过早引入外部队列和多进程部署复杂度。
- 数据库任务队列能持久保存任务、步骤、日志和产物信息，前端可稳定轮询。

## 配置项

新增配置项：

```text
DPT_JAR_PATH=/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar
DPT_WORK_DIR=/tmp/beetleshield-hardening
DPT_DEFAULT_VMP_RULES=**
DPT_TASK_TIMEOUT_MINUTES=60
```

`DPT_DEFAULT_VMP_RULES` 的实际默认文件内容为：

```text
# 全量探测保护 (依赖内置规则引擎进行智能避让)
**
```

如果环境变量只配置规则正文，则服务层负责补齐注释或直接按配置内容写入任务工作目录。

## 数据模型

### hardening_tasks 表

保存一次加固任务主记录。

| 字段 | 类型 | 说明 |
|---|---|---|
| id | uint (PK) | |
| task_no | string, unique | 展示用任务号，例如 `TASK-20260702-000001` |
| app_id | uint, index | 关联 `apps.id` |
| status | string | `queued` / `running` / `completed` / `failed` |
| strategy_name | string | 展示名，例如“默认加固模板”“信息院 App 加固模板” |
| strategy_snapshot | json | 执行时策略快照，避免历史任务受后续策略修改影响 |
| vmp_rules_text | text | 执行时 VMP 规则文本快照 |
| enable_file_integrity_check | bool | 是否启用文件完整性校验 |
| enable_proxy_detect | bool | 是否启用代理检测 |
| unsigned_object_key | string | 未签名加固产物 MinIO object key |
| unsigned_file_size | int64 | 未签名产物大小 |
| unsigned_sha256 | string | 未签名产物 SHA256 |
| signed_test_object_key | string | 测试签名产物 MinIO object key，可为空 |
| signed_test_file_size | int64 | 测试签名产物大小 |
| signed_test_sha256 | string | 测试签名产物 SHA256 |
| error_summary | string | 失败摘要 |
| created_by | uint | 发起人 |
| started_at | *time.Time | |
| finished_at | *time.Time | |
| created_at / updated_at | time.Time | |

任务状态流转：

```text
queued -> running -> completed
queued -> running -> failed
```

第一版不支持取消和重试。

### hardening_steps 表

保存前端六步流程。

| 字段 | 类型 | 说明 |
|---|---|---|
| id | uint (PK) | |
| task_id | uint, index | |
| step_key | string | 稳定步骤 key |
| name | string | 中文展示名 |
| status | string | `waiting` / `running` / `success` / `failed` |
| sort_order | int | 展示顺序 |
| started_at | *time.Time | |
| finished_at | *time.Time | |
| error_message | string | 该步骤失败信息 |
| created_at / updated_at | time.Time | |

固定步骤：

| step_key | 展示名 | 说明 |
|---|---|---|
| prepare_input | 准备输入 | 创建工作目录，从 MinIO 下载原始包，写 VMP 规则文件 |
| parse_package | 解析包体 | 记录应用包名、版本、文件信息；第一版复用已有应用元数据 |
| apply_strategy | 应用策略 | 根据策略快照生成 dpt 命令参数 |
| run_engine | 执行加固 | 执行 `java -jar dpt.jar` |
| collect_artifacts | 收集产物 | 校验未签名产物，发现测试签名产物 |
| upload_artifacts | 上传产物 | 上传 MinIO，写回产物元数据 |

### hardening_logs 表

按行保存加固日志。

| 字段 | 类型 | 说明 |
|---|---|---|
| id | uint (PK) | |
| task_id | uint, index | |
| step_id | *uint, index | 可为空 |
| level | string | `info` / `warn` / `error` / `success` |
| message | text | 日志内容 |
| created_at | time.Time | |

dpt.jar 的 stdout/stderr 全部写入日志。后端自身步骤也写日志，便于前端日志弹窗按步骤展示。

### apps 表状态联动

沿用已有 `apps.status`：

- 创建任务成功：`processing`
- 任务成功：`completed`
- 任务失败：`failed`
- 上传后未加固：`unprotected`

同一个应用存在 `queued` 或 `running` 任务时，创建新任务返回 409，避免重复加固。

## 策略与模板处理

流水线不把模板写死为行业分类。模板语义为“项目/客户产品交付模板”，例如：

- 默认加固模板
- 信息院 App 加固模板
- 数智学院 App 加固模板

本子项目不重做策略模板管理。创建任务时可传：

- `strategyName`
- `strategySnapshot`
- `vmpRulesText`
- `enableFileIntegrityCheck`
- `enableProxyDetect`

如果 `strategySnapshot` 为空，后端读取当前全局策略作为快照。如果 `strategyName` 为空，使用“默认加固模板”。如果 `vmpRulesText` 为空，使用默认全量探测规则。

历史任务只展示保存的 `strategyName` 和 `strategySnapshot`，不回查当前策略。

## dpt.jar 命令映射

后端执行命令形态：

```shell
java -jar <DPT_JAR_PATH> \
  -f <task-workdir>/input.<apk|aab> \
  -o <task-workdir>/output.<apk|aab> \
  --no-sign \
  <strategy args>
```

用户常用命令基线：

```shell
java -jar dpt.jar -f ./app-release.apk \
  --enable-emulator-detect \
  --no-sign \
  --enable-apk-sig-verify --apk-sig-policy block \
  --enable-file-integrity-check \
  --enable-hook-detect \
  --enable-proxy-detect \
  --enable-root-detect \
  --enable-assets-encrypt \
  --enable-vmp --vmp-rules vmp-rules.txt
```

注意：dpt.jar 帮助信息中 VMP 规则参数为 `-Y` 或 `--vmp-rules`。后端使用长参数 `--vmp-rules`。

策略映射：

| 策略字段或任务参数 | dpt 参数 |
|---|---|
| `emulator=true` | `--enable-emulator-detect` |
| `rootDetect=true` | `--enable-root-detect` |
| `signature=true` | `--enable-apk-sig-verify --apk-sig-policy block` |
| `antiHook=true` | `--enable-hook-detect` |
| `frida=true` 或 `xposed=true` | `--enable-hook-detect` |
| `stringEncrypt=true` | `--enable-string-encrypt` |
| `resEncrypt=true` | `--enable-assets-encrypt` |
| `dexLevel=high` | `--enable-vmp --vmp-rules <rules-file>` |
| `soShell=vmp` | `--enable-vmp --vmp-rules <rules-file>` |
| `enableFileIntegrityCheck=true` | `--enable-file-integrity-check` |
| `enableProxyDetect=true` | `--enable-proxy-detect` |

`debugger` 第一版不强行映射到代理检测；代理检测由 `enableProxyDetect` 控制，并可作为高强度项目模板的默认项。

`soStrength`、`targetSos`、`dexLevel` 的更细粒度能力先保存到策略快照。当前 dpt.jar 没有直接等价参数时，不在第一版强行翻译。

## Worker 执行流程

服务启动时启动一个串行 worker goroutine。

执行流程：

```text
1. 恢复遗留 running 任务为 failed。
2. 循环查询最早 queued 任务。
3. 抢占任务并置为 running，写 started_at。
4. 创建固定六个 hardening_steps，或使用创建任务时已初始化的步骤。
5. prepare_input：
   - 创建 {DPT_WORK_DIR}/{task_no}/
   - 从 MinIO 下载原始 APK/AAB
   - 写 vmp-rules.txt
6. parse_package：
   - 记录应用名称、包名、版本、原始文件 hash 等已有元数据
7. apply_strategy：
   - 生成命令参数并写日志
8. run_engine：
   - 带 timeout 执行 dpt.jar
   - stdout/stderr 按行写 hardening_logs
9. collect_artifacts：
   - 校验未签名产物存在且大小 > 0
   - 尝试收集测试签名产物
10. upload_artifacts：
   - 上传未签名产物到 MinIO
   - 如果测试签名产物存在，也上传
   - 计算大小和 SHA256
11. 标记任务 completed，更新 apps.status=completed。
```

失败时：

- 当前步骤置为 `failed`。
- 后续步骤保持 `waiting`。
- 任务置为 `failed`，写 `error_summary`。
- `apps.status` 置为 `failed`。
- 保留所有已写入日志。

服务启动恢复：

- 将遗留 `running` 任务统一标记为 `failed`。
- 对应 `running` 步骤标记为 `failed`。
- `apps.status` 标记为 `failed`。
- 错误摘要写“服务重启导致任务中断”。
- 第一版不自动重试。

成功判定：

- dpt.jar 进程结束。
- 未签名产物存在且大小 > 0。
- 未签名产物上传 MinIO 成功。

dpt.jar 入口捕获异常后可能只打印 stack trace 而不主动 `System.exit(1)`，所以不能只依赖退出码。产物存在是主成功条件；如果日志出现明显错误但产物存在，第一版仍以产物校验为准，并保留日志供人工判断。

## 产物规则

`--no-sign` 下，未签名包是默认交付产物。dpt.jar 还可能生成测试签名包，便于真机测试。产物扩展名跟随原始文件类型，APK 输入生成 APK 产物，AAB 输入生成 AAB 产物。

后端保存两类产物：

| artifact | 说明 | 下载默认 |
|---|---|---|
| `unsigned` | 未签名加固包，交付给用户或 CI 后续正式签名 | 是 |
| `signed_test` | 引擎生成的测试签名包，用于真机验证 | 否 |

`GET /hardening-tasks/:id/download-url` 默认返回 `unsigned`。请求 `artifact=signed_test` 时，如果任务没有测试签名产物，返回 404。

## API 设计

统一前缀 `/api/v1`，沿用已有响应结构 `{code, message, data}`。

### POST /hardening-tasks

从已有应用发起加固。

权限：`admin` / `developer`。

请求：

```json
{
  "appId": 123,
  "strategyName": "信息院 App 加固模板",
  "strategySnapshot": {
    "emulator": true,
    "rootDetect": true,
    "signature": true,
    "antiHook": true,
    "frida": true,
    "xposed": true,
    "stringEncrypt": true,
    "resEncrypt": true,
    "dexLevel": "high",
    "soShell": "vmp",
    "soStrength": 90,
    "targetSos": ["libnative-lib.so"]
  },
  "vmpRulesText": "# 全量探测保护\n**",
  "enableFileIntegrityCheck": true,
  "enableProxyDetect": true
}
```

规则：

- `appId` 必填，应用必须存在。
- 应用存在 `queued/running` 任务时返回 409。
- `strategySnapshot` 不传时读取当前全局策略。
- `strategyName` 不传时使用“默认加固模板”。
- `vmpRulesText` 空时使用默认全量规则。
- 创建任务后初始化六个步骤，任务状态为 `queued`，应用状态为 `processing`。

响应：任务详情。

### GET /hardening-tasks

任务历史列表。

权限：任意登录角色。

查询参数：

```text
page
pageSize
status
appId
search
```

`search` 匹配任务号、应用名、包名。

响应包含任务概要、应用信息、策略名、状态、当前步骤、耗时和产物可下载状态。

### GET /hardening-tasks/:id

任务详情。

权限：任意登录角色。

响应包含：

- 任务主信息
- 应用名称、包名、版本
- 策略名和策略快照
- 六个步骤
- 产物信息
- 错误摘要
- 最近日志摘要

### GET /hardening-tasks/:id/logs

查询任务日志。

权限：任意登录角色。

查询参数：

```text
stepKey
afterId
limit
```

`afterId` 支持前端增量轮询。

### GET /hardening-tasks/:id/download-url

生成产物预签名下载 URL。

权限：第一版默认任意登录角色可下载，保持只读角色能验证产物。如后续认定产物敏感，可在实现计划阶段收紧为 `admin/developer`。

查询参数：

```text
artifact=unsigned
artifact=signed_test
```

默认 `artifact=unsigned`。

### GET /apps/:id/hardening-history

查询应用最近 5 次加固历史，供应用详情抽屉展示。

权限：任意登录角色。

响应为任务概要列表。

## 前端页面适配

应用管理页：

- “加固”按钮调用 `POST /hardening-tasks`。
- 创建成功后可跳转 `/pipeline` 并选中新任务。
- “下载”默认下载最近成功任务的未签名产物，后续可增加下拉选择测试签名产物。
- 应用详情抽屉调用 `/apps/:id/hardening-history` 展示最近 5 次。

流水线页：

- 任务下拉和历史列表调用 `GET /hardening-tasks`。
- 任务详情调用 `GET /hardening-tasks/:id`。
- 步骤日志弹窗调用 `GET /hardening-tasks/:id/logs?stepKey=...`。
- `queued/running` 任务定时轮询详情和日志。
- 产物下载调用 `GET /hardening-tasks/:id/download-url`。

## 错误码建议

沿用现有业务错误码风格，新增范围：

| HTTP | code | 场景 |
|---|---:|---|
| 400 | 40020 | 非法任务参数 |
| 400 | 40021 | 非法任务 ID |
| 404 | 40410 | 加固任务不存在 |
| 404 | 40411 | 加固产物不存在 |
| 409 | 40910 | 应用已有进行中的加固任务 |
| 500 | 50020 | 创建加固任务失败 |
| 500 | 50021 | 查询加固任务失败 |
| 500 | 50022 | 生成产物下载链接失败 |

worker 内部失败不直接返回 HTTP 500，而是写入任务状态和日志。

## 测试策略

Repository 测试：

- 创建任务和六个步骤。
- 查询最早 queued 任务。
- 列表过滤：状态、appId、search、分页。
- 检查同一应用是否存在 queued/running 任务。
- 日志按 `afterId` 和 `stepKey` 分页。
- 应用加固历史最近 5 条。

Service 测试：

- 不传策略时回落当前全局策略。
- 不传 VMP 规则时写默认 `**`。
- 自定义 VMP 规则覆盖默认规则。
- 策略快照生成 dpt 参数。
- `--vmp-rules` 使用任务工作目录规则文件。
- 未签名产物必需，测试签名产物可选。

Worker 测试：

- 使用 fake engine runner，不在单测中真实执行 dpt.jar。
- 成功路径：任务 completed、步骤全 success、apps.status=completed、两个产物上传。
- 无测试签名产物：任务仍 completed，写 warn 日志。
- 无未签名产物：任务 failed，apps.status=failed。
- 引擎返回错误或超时：任务 failed。
- 启动恢复 running 任务为 failed。

Handler 测试：

- `admin/developer` 可创建任务。
- `auditor` 创建任务返回 403。
- 重复进行中任务返回 409。
- 列表、详情、日志、下载参数校验。
- `signed_test` 不存在返回 404。

手动 smoke 测试：

- 保留一个脚本或 Makefile 目标，使用本地真实 dpt.jar 和测试 APK 手动跑完整链路。
- 该 smoke 测试不作为默认 `make test` 的硬依赖，避免 CI 或其他开发机缺少 jar/Java/测试 APK。

## 后续扩展

1. 策略中心升级为可配置项目模板表，支持客户、项目、产品维度维护模板。
2. 增加任务取消、重新执行、失败重试。
3. 将进程内 worker 拆分为独立 worker 进程，或接入外部队列。
4. 支持并发度配置和任务优先级。
5. 报告模块基于任务产物和日志生成加固前后对比。
6. 日志审计模块纳入任务创建、下载、失败等操作审计。
