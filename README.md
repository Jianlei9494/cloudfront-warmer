# cf-warmer：用自己 AWS 账号预热 CloudFront 缓存

在你自己的 AWS 账号里，于多个区域各部署一个小 Lambda。每个 Lambda 对目标地址发一次完整 GET，
请求落到离该区域最近的 CloudFront 边缘节点，对象随之进入该节点及其区域边缘缓存（REC）。
所有资源和费用都在你自己的账号里，不依赖任何第三方服务，也不需要把任何凭证交给别人。

有两种用法，任选其一：

| | 网页面板（推荐） | 命令行 |
|---|---|---|
| 部署 | CloudFormation 上传模板，填一个口令 | CloudShell 里一条命令 |
| 日常使用 | 浏览器打开面板，贴地址，点按钮 | 一条命令 |
| 预热记录 | 保存 90 天，可回看 | 无 |
| 文件 | `cf-warmer.template.json` | `cf_warmer.py` |

---

## 方式一：网页面板

### 一键部署（推荐，约 3 分钟）

1. 登录 AWS 控制台，点右上角的 **CloudShell** 图标（`>_`）。
2. 粘贴这一行并回车（下载最新的 `install.sh` 并运行，不需要上传任何文件）：
   ```bash
   curl -sLO https://raw.githubusercontent.com/Jianlei9494/cloudfront-warmer/main/install.sh && bash install.sh
   ```
3. 结束时屏幕上会显示**面板地址**和**自动生成的口令**，保存好，打开地址登录即可。

CloudShell 访问不了 GitHub 时，从 https://raw.githubusercontent.com/Jianlei9494/cloudfront-warmer/main/install.sh 下载文件，在「操作 → 上传文件」上传后运行 `bash install.sh`。
下面的 `bash install.sh` 都假定文件已在 CloudShell 里（第一次运行后就在了）；想拿最新版就先 `curl -sLO https://raw.githubusercontent.com/Jianlei9494/cloudfront-warmer/main/install.sh`。

- 想自己定口令：`CFW_PASSWORD='至少12位的口令' bash install.sh`
- 只允许部分域名：`CFW_ALLOWED_HOSTS='cdn.example.com' bash install.sh`（默认不限制）
- 忘记口令 / 升级到新版本：重新运行 `bash install.sh`（会生成新口令，预热记录保留）
- 卸载：`bash install.sh uninstall`（文件不在了就先 `curl -sLO https://raw.githubusercontent.com/Jianlei9494/cloudfront-warmer/main/install.sh`）

### 手动部署（不用命令行）

1. 登录 AWS 控制台，切换到 **us-east-1（美东-弗吉尼亚）**（其他区域也可以，面板就建在你选的区域）。
2. 先下载模板 https://raw.githubusercontent.com/Jianlei9494/cloudfront-warmer/main/cf-warmer.template.json ，再打开 **CloudFormation → 创建堆栈 → 使用新资源**，选「上传模板文件」上传它。
3. 堆栈名称填 `cf-warmer`；**面板访问口令**填一个至少 12 位的口令。其余参数保持默认即可。
   「允许预热的域名」默认留空，即不限制；如只想允许自己的域名，可在这里填写（逗号分隔），之后也能通过「更新堆栈」修改。
4. 一路「下一步」，最后勾选「我确认 AWS CloudFormation 可能创建 IAM 资源」，点「提交」。
5. 状态变成 `CREATE_COMPLETE` 后，打开「输出」页签：
   - `PanelURL`：面板地址，收藏它
   - `DeployedRegions` / `FailedRegions`：哪些区域部署成功

也可以在 CloudShell 里一条命令部署：

```bash
aws cloudformation deploy --region us-east-1 --stack-name cf-warmer \
  --template-file cf-warmer.template.json --capabilities CAPABILITY_IAM \
  --parameter-overrides AccessPassword='你的口令' AllowedHosts='cdn.example.com'
```

### 使用

1. 打开 `PanelURL`，输入口令登录（12 小时内免登录）。
2. 每行贴一个完整的 https 地址。
3. 选预热范围：
   - **全覆盖**：每个区域都热，各地首次访问都快
   - **经济**：只从一个区域热。分发开了 Origin Shield 时用这个，源盾拿到对象后其他区域首次访问不再回源，流量只有全覆盖的一小部分
4. 点「预检并估算流量」，确认预计流量后点「确认预热」。
5. 结果是一张「地址 × 区域」的表格：绿色「已命中」= 已缓存；黄色「已下载」= 下载完成但复查未命中；红色「失败」，鼠标悬停看原因、服务节点和响应头。
6. 也可以不立即执行，选时间点「预定在这个时间执行」（单次，最多提前 30 天）。到点自动执行，右侧「预定任务」可查看、取消。
   - **按目录预热**：第 2 步选「按目录」，填目录。两种指定方式：选本账号分发（面板读分发配置找到该目录对应的 S3 源站，含源站组主源站，
     并按缓存行为过滤掉由其他源站提供的路径）；或「手动填写」访问域名 + 存储桶 + 源站路径（分发或存储桶在其他账号时用，不做缓存行为过滤）。
     列出桶里的全部文件（含子目录），按源站路径换算成 CloudFront 地址；空文件跳过并列出原因；预览时 HEAD 抽查第一个文件。
     存储桶在其他账号时，预览返回 403 + 一段只授 `s3:ListBucket`、`Principal` 为面板角色、`s3:prefix` 限定到该目录的桶策略，桶主人加上即可。
     确认后后台分批执行（可立即或预定），右侧「后台任务」看进度、取消、查看失败明细。
     只支持源站是本账号 S3 桶的分发（含源站组的主源站）
7. 右侧「最近记录」可回看过去 90 天的预热结果，预定执行的带 ⏰ 标记。

高级选项里可以选多种压缩格式、加请求头（如签名 Cookie）。

### 修改 / 删除

- 改口令、域名白名单、区域：CloudFormation → 选中堆栈 → 更新 → 使用当前模板 → 改参数
- 升级到新版本：更新堆栈时上传新的模板文件
- 删除：推荐 `bash install.sh uninstall`，会删掉堆栈（各区域预热 Lambda、面板、记录表、IAM 角色）和各区域的运行日志。
  只在 CloudFormation 控制台删除堆栈的话，`/aws/lambda/cf-warmer*` 日志组会留下，需要到 CloudWatch 日志里手动删

### 会在你的账号里创建什么

| 资源 | 数量 | 说明 |
|---|---|---|
| Lambda `cf-warmer` | 每个区域 1 个（默认 13 个） | 执行预热，只发 GET / HEAD |
| Lambda `cf-warmer-panel` + 函数 URL | 1 个 | 网页面板，口令登录 |
| Lambda `cf-warmer-installer` | 1 个 | 部署 / 删除各区域的 `cf-warmer`，只在创建、更新、删除堆栈时运行 |
| DynamoDB 表 | 1 张 | 存口令的哈希、预热记录和预定任务（90 天自动过期），按量计费 |
| EventBridge 规则 | 1 条 | 每分钟唤醒面板一次，执行到点的预定任务、推进后台任务 |
| IAM 角色 | 3 个 | 各自只有所需的最小权限 |
| CloudWatch 日志组 | 每个函数 1 个 | 运行日志，保留 30 天后自动删除 |

`me-central-1`（中东-阿联酋）需要先在账号设置里启用。未启用时该区域会出现在 `FailedRegions` 里，其他区域照常可用。

---

## 方式二：命令行

最简单是在 AWS 控制台的 **CloudShell** 里运行（自带 Python 和 boto3，已登录，无需配置密钥）。
在自己电脑上运行需要 Python 3.10+、`pip install boto3` 和 `aws configure`。

```bash
python3 cf_warmer.py deploy                         # 部署（一次）
python3 cf_warmer.py run https://cdn.example.com/app.js --verify
python3 cf_warmer.py run -f urls.txt --verify       # 一行一个地址，# 开头为注释
python3 cf_warmer.py status                         # 查看各区域状态
python3 cf_warmer.py destroy                        # 删除全部资源
```

| 参数 | 作用 |
|---|---|
| `--regions us-east-1,ap-southeast-1` | 只用部分区域（写在子命令前面） |
| `--mode economy --economy-region us-east-1` | 只从一个区域预热（适合开了 Origin Shield 的分发） |
| `--encodings 'br\|gzip\|identity'` | 预热多种压缩格式，默认只热浏览器常用的 `gzip, deflate, br` |
| `-H 'Cookie: CloudFront-Policy=...'` | 附加请求头 |
| `--verify` | 预热后再发一次 HEAD，确认已命中 |
| `--max-mb 1024` | 单个对象大小上限（默认 0 = 不限） |
| `--json` | 输出 JSON |
| `-y` | 跳过确认 |

退出码：0 全部成功，2 有失败项。

运行身份需要的权限：`iam:CreateRole`、`iam:GetRole`、`iam:PutRolePolicy`、`iam:DeleteRolePolicy`、`iam:DeleteRole`、`iam:PassRole`，
以及 `lambda:CreateFunction`、`lambda:UpdateFunctionCode`、`lambda:UpdateFunctionConfiguration`、`lambda:GetFunction`、
`lambda:GetFunctionConfiguration`、`lambda:DeleteFunction`、`lambda:InvokeFunction`，以及 `logs:CreateLogGroup`、`logs:PutRetentionPolicy`（设日志保留期，没有也不影响使用）。管理员账号直接满足。

两种方式部署的预热 Lambda 同名（`cf-warmer`），二选一使用即可。

---

## 结果怎么看

- **节点**：服务这次请求的 CloudFront 边缘节点（`X-Amz-Cf-Pop`）
- **首次**：预热请求本身的 `X-Cache`。`Miss` 表示这次是回源拉的，正常
- **复查**：预热后 HEAD 的结果。`Hit from cloudfront` = 已缓存。
  同一节点有多台缓存服务器，复查未命中时会间隔 2 秒重试，最多 3 次。
  重试后仍是 `Miss` 通常是对象带了 `Cache-Control: no-cache / no-store / private`，或缓存策略 TTL 为 0，这类对象预热无效
- 重定向、4xx / 5xx、下载不完整、Lambda 超时都算失败，不会当成成功

## 限制

- 每个区域只热离它最近的那个边缘节点和对应的区域边缘缓存，不是全部几百个节点。其他节点首次访问时会从已热的区域边缘缓存取，不再回源
- 缓存键要与真实访客一致才有效：完整地址（含 query）、压缩格式、缓存策略里配置的请求头 / Cookie
- 默认不限文件大小、地址数和目录文件数。唯一硬限制：单个文件要在预热函数的 15 分钟内下载完。
  面板按各区域实测下载速度（只用 ≥ 2 MB 的样本）预估，可能超时的标黄提示但不拦截；默认内存 2048 MB，可用 `CFW_WORKER_MEMORY_MB` 调大
- 客户可自我约束：`CFW_MAX_OBJECT_MB`、`CFW_MAX_DIR_FILES`（install.sh 每次运行都以这些变量为准，默认 0 = 不限）
- 一次提交的地址受函数 URL 请求体 6 MB 限制，约 2 万个；更多请分次或用「按目录」
- 只能预热具体对象，不支持通配符；按目录预热的源站必须是 S3，经 CloudFront Functions / Lambda@Edge 改写路径的分发换算出的地址可能不对（会如实报失败）
- 只能预热经过 CloudFront 的地址：预检和预热时都检查响应头（`X-Amz-Cf-Pop` / `Via`），源站地址和别家 CDN 会被跳过，不会下载正文；「已命中」只认 `Hit from cloudfront`

## 费用（全部计入你自己的 AWS 账单）

- **CloudFront**：每次预热 = 区域数 × 压缩格式数 次完整下载，按你账号的 CloudFront 流量和请求费率计费；未开 Origin Shield 时回源次数也随区域数增加。面板和命令行在执行前都会显示预计流量
- **Lambda / DynamoDB**：按调用次数和时长计费，通常远小于 CloudFront 流量费；不使用时不产生费用

---

## 维护（给发布方）

`cf-warmer.template.json` 和 `install.sh`（内嵌同一份模板）由 `build_template.py` 从源码生成，不要手改：

- 预热 Lambda 代码：`cf_warmer.py` 里的 `LAMBDA_SOURCE`（命令行版与模板共用）
- 面板：`src/panel.py` + `src/panel.html`
  - 预定任务：`pk=sched` 记录，`rate(1 minute)` 规则直接调用面板函数（事件无 `requestContext`，函数 URL 请求无法伪造此分支）；
    到点用条件更新 `pending→running` 认领，保证只执行一次；`running` 超过 20 分钟判为中断失败
  - 后台任务（目录 / 超过 20 个地址 / 地址多的预定）：`pk=dir` 记录，文件清单分块存 `pk=jobf#<id>`（每块 1000 个，不受单条 400 KB 限制）。
    定时唤醒用条件更新抢租约（`lease_until`）；每批先 HEAD 预检，再**异步**调用各区域预热函数（`InvocationType=Event`），
    预热函数把结果写回 `pk=res#<id>`，面板汇总后推进进度。批大小按「文件 × 区域 × 编码 ≤ 600」且 ≤ 200 个文件。
    结果没回齐就释放租约下一分钟再看（不判失败）；超过「排队 20 分钟 + 运行 15 分钟 + 1 分钟」仍没回报的调用记为失败。
    预热函数的异步调用设为不重试、最长排队 20 分钟（安装器 `put_function_event_invoke_config`），避免超时后重复下载。
    进度保存带「状态仍为 running 且租约是自己的」条件，取消后已发出的这批跑完即停
  - 实测速度：`pk=config, sk=speed`，各区域字节 / 秒，按批次中位数做滑动平均
  - 面板角色新增只读权限：`cloudfront:ListDistributions` / `GetDistribution` / `GetDistributionConfig`、`s3:ListBucket`
- 安装器：`src/installer.py`（CloudFormation 内联代码，上限 4096 字符，构建时会检查）

```bash
python3 build_template.py          # 重新生成模板
python3 build_template.py --check  # 检查模板是否与源码一致
```

**发布**：公开仓库 https://github.com/Jianlei9494/cloudfront-warmer 的 `main` 就是客户部署时下载的版本（`https://raw.githubusercontent.com/Jianlei9494/cloudfront-warmer/main/install.sh`），
推送即生效。改完先 `python3 build_template.py --check` 并在测试账号跑通，再推送。
本目录是开发源，公开仓库是发布副本，两边内容保持一致（同步方法：把 `git ls-files` 列出的文件复制到公开仓库后提交）。

如需「一键部署」链接，把模板上传到公开可读的 S3 后，链接格式为（CloudFormation 只接受 S3 地址，不接受 GitHub 地址）：
`https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate?stackName=cf-warmer&templateURL=<模板的 S3 HTTPS 地址>`
