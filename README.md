# EmailSendSystem

任务列表支持筛选：`GET /api/v1/messages?status=queued&id=<完整任务ID>&created_from=<Unix秒>&created_to=<Unix秒>&page=1&page_size=20`。各筛选参数均可省略；状态和 ID 精确匹配，创建时间包含两端。响应新增 `total`，表示筛选及权限共同匹配的总数。发送 Token 的条件不能突破任务所有权限制。

个人使用的 Go 邮件账号池后端。通过服务商 SMTP 465/587 发送，提供 REST API、持久化队列和自动账号选择。没有前端、附件、短信、定时发送及 OAuth。无需 Redis、MySQL 或 Docker。

## 快速启动：Windows / VS Code

在 VS Code 中打开 `D:\EmailSendSystem`，打开 PowerShell 终端。Go 安装位置为 `D:\Go`；新终端可以执行 `go version`。若旧进程未刷新 PATH，可临时执行：

```powershell
$env:Path = "D:\Go\bin;" + $env:Path
go version
go mod download
Copy-Item config.example.json config.json
go run ./cmd/emailsend init -config config.json
go run ./cmd/emailsend serve -config config.json
```

首次 `init` 要求数据目录不存在，绝不覆盖已有密钥或 Token。初始化生成 `data/master.key`、`data/key.check`、`data/admin.token` 和数据库。Windows 请通过目录 ACL 限制其他用户读取；Unix 文件使用 0600、目录 0700。

如果官方 Go 代理无法访问，可以仅在当前终端设置可信镜像，保留 checksum 校验：

```powershell
$env:GOPROXY = "https://goproxy.cn,direct"
go mod download
```

不要将授权码、数据目录或配置提交到 Git。后台默认仅监听 `127.0.0.1:8080`。关闭时按 Ctrl+C，最多等待 65 秒完成已领取的发送。

## 调用示例

另开一个 PowerShell 终端，在项目根目录执行。以下读取 Token 但不打印。

```powershell
$admin = (Get-Content data/admin.token -Raw).Trim()
$headers = @{ Authorization = "Bearer $admin" }
$accountBody = @{
    name = "我的 QQ 邮箱"
    host = "smtp.qq.com"
    port = 465
    tls = "implicit"
    username = "你的邮箱@qq.com"
    secret = "你的SMTP授权码"
    from = "你的邮箱@qq.com"
    display_name = "邮件通知"
    per_minute = 2
    daily_limit = 100
} | ConvertTo-Json
$account = Invoke-RestMethod http://127.0.0.1:8080/api/v1/accounts `
    -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' `
    -Body ([System.Text.Encoding]::UTF8.GetBytes($accountBody))

# 只测试 TLS 和认证，不向外发送邮件。
Invoke-RestMethod "http://127.0.0.1:8080/api/v1/accounts/$($account.id)/test" `
    -Method Post -Headers $headers

# 给脚本签发受限 Token。secret 只在本次响应出现，妥善保存。
$token = Invoke-RestMethod http://127.0.0.1:8080/api/v1/tokens `
    -Method Post -Headers $headers -ContentType application/json `
    -Body (@{ name = 'my-script'; account_ids = @($account.id) } | ConvertTo-Json)
$sendHeaders = @{
    Authorization = "Bearer $($token.secret)"
    'Idempotency-Key' = [guid]::NewGuid().ToString()
}
$mailBody = @{
    to = '你自己的测试收件邮箱@example.com'
    subject = '第一封测试邮件'
    text = '你好，这是测试正文。'
} | ConvertTo-Json
$task = Invoke-RestMethod http://127.0.0.1:8080/api/v1/messages `
    -Method Post -Headers $sendHeaders -ContentType 'application/json; charset=utf-8' `
    -Body ([System.Text.Encoding]::UTF8.GetBytes($mailBody))
Invoke-RestMethod "http://127.0.0.1:8080$($task.status_url)" -Headers $sendHeaders
```

163 的常用 SMTP 主机是 `smtp.163.com`；实际参数和 SMTP 授权开通状态以邮箱服务商控制台为准。SMTP 账号只支持允许程序认证的 PLAIN/LOGIN，不支持 OAuth。

必须使用账号允许的固定发件地址。自动选账号可能改变发件身份；填写 `account_id` 可以固定账号。默认每分钟 2 次、每天 100 次是应用的保守预算，不是邮箱服务商额度。每次真实尝试都计入预算，预算按北京时间每日重置，分钟预算是从当前窗口首个尝试开始的 60 秒固定窗口。

## API 语义

完整机器可读接口：[docs/openapi.json](docs/openapi.json)。所有业务接口使用 Bearer Token。账号、Token、统计管理要求管理员；发送 Token 仅能查看、取消、重发自己的任务。

账号支持 PATCH 配置及 `enabled`，未提供字段保持原值，空 `secret` 不覆盖凭据；更新可能返回版本冲突，重新获取账号后重试。停用不删除历史。认证失败后更换授权码会恢复可用；连接测试只返回测试结果，不修改账号状态。管理员 Token 不允许通过撤销接口撤销。

| 状态 | 意义 |
|---|---|
| queued | 已持久化，等待账号和额度 |
| sending | 已领取，预算已计入，正在尝试 |
| retry_wait | 明确未被接受的临时失败，等待重试 |
| submitted | SMTP 服务商已接受，不代表收件箱或阅读 |
| failed | 永久错误、重试耗尽、过期或身份已撤销 |
| unknown | 提交结果不确定，不自动重发 |
| cancelled | 用户取消，尚未执行 |

`POST /messages` 和重发要求 `Idempotency-Key`。同一 Token 的键和请求相同则返回原任务，内容不同返回 409。保证窗口为任务保留期 30 天。只有 `failed` / `unknown` 可以重发，重发创建新任务；unknown 需要请求正文 `{"confirm_possible_duplicate":true}`。正文过期不可直接重发。每个请求只有一个收件人。

重试最多 3 次，间隔 1 分钟、5 分钟；限流使账号冷却 30 分钟。自动任务仅在明确未接受后才可能换账号。内容写出后的网络错误为 unknown。意外终止时所有 sending 转为 unknown，避免重复；不能保证邮件恰好发送一次。

发送接口返回 202 表示已经落库。400 参数错误，401 鉴权失败，403 越权，404 不存在，409 状态/版本/幂等冲突，429 请求限流，503 容量耗尽。错误均包含 `error.code`、`error.message`、`error.request_id`。认证和错误回复不回传 SMTP 原始回复。

列表默认 20 条、最多 100 条，仅包含任务元数据；详情包含正文及最多三次尝试。每条尝试保存真实发件地址，账号配置后续变化不影响历史。正文保留 7 天，任务和幂等数据保留 30 天；每分钟小批清理。

## 资源控制

配置参考 `config.example.json`。4 个 worker，每账号 1 并发；SMTP 总超时 60 秒；测试并发 2；活跃 HTTP 请求最多 64。JSON 最多 512KiB，正文最多 256KiB。未完成队列最多 1000 个 / 32MiB 正文。Token 数量最多 256、账号最多 128，撤销身份仍占容量用于历史引用。每 Token 默认 20 请求/秒、突发 40。

Go 内存软目标为 128MiB；这是 GC 目标，不是进程 RSS 硬限制。Linux systemd `MemoryMax=256M` 是独立进程限制。请求上限和有界任务队列避免积压加载到内存；连接数量还应通过 Nginx 和系统资源配置管理。

`/health/live` 为存活检查，`/health/ready` 检查数据库可访问及调度器是否健康；管理员 `/api/v1/stats` 返回队列状态、账号预算、Go 堆和 goroutine 数量。堆大小不是 RSS。结果落库失败时该 worker 停止继续领取，readiness 返回 503，错误写入日志，原任务保留 sending；排查并重启后恢复为 unknown。

## 编译与检查

```powershell
go test ./...
go vet ./...
# race 需要 CGO 和可用的 C 编译器。
go test -race ./...
go build -trimpath -o bin/emailsend.exe ./cmd/emailsend
$env:CGO_ENABLED = '0'
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
go build -trimpath -ldflags='-s -w' -o bin/emailsend-linux-amd64 ./cmd/emailsend
```

自动化集成测试在本机启动可信测试证书的 SMTP 服务，不向外发送邮件。测试报告见 `docs/verification.md`。真实服务商投递需要用户授权码和测试收件地址，未在自动化测试中发送。

## Linux 部署与备份

把 Linux 二进制放在 `/opt/emailsend/emailsend`，配置放在 `/opt/emailsend/config.json`。创建专用用户 `emailsend`；配置 `data_dir` 为 `/var/lib/emailsend/data`，确保其父目录可由该用户写入。以该用户执行 `init`，再安装 `deploy/emailsend.service` 和修改域名、证书路径后的 `deploy/nginx.conf`。仅向公网开放 HTTPS，不开放 Go 监听端口。

日志输出到 stdout，由 journald 管理；部署机器应限制 journal 总量（例如 `SystemMaxUse=100M`、`MaxRetentionSec=7day`），Nginx 日志使用系统 logrotate。配置文件中的队列和内存上限只能在验证后修改。

第一版只支持一个进程，跨平台文件锁阻止同一数据目录并行启动。升级前停服，使用旧二进制执行：

```text
emailsend backup -config /opt/emailsend/config.json -out /safe/location/mail-backup.db
```

`VACUUM INTO` 创建一致性备份，目标文件必须不存在。备份命令要求停服，SQLite 一致性实现也用于升级前迁移快照。备份期间不要复制活跃 WAL 数据库文件。

还需安全备份主密钥、key.check 和配置，主密钥与数据库备份分开存放。恢复时停服，将快照作为 `mail.db` 放入新的数据目录，并配置对应主密钥和校验文件；启动会校验主密钥。部署回滚使用旧程序与升级前完整备份；拒绝直接打开比程序更新的数据库版本。

SMTP 主机配置属于管理员信任边界，管理员 Token 等同于管理邮件渠道的权限，应只授权给本人。真实账号池不能用于突破服务商额度，服务商拒收不应通过盲目轮换重试。
