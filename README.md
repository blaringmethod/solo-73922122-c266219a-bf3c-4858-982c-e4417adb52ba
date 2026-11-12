# mTLS 证书链离线诊断工具（mtls-chain-doctor）

内网 mTLS 运维排障场景：网关拒绝客户端证书时，区分两类根因——

1. **中间证书缺失**：叶子/中间证书的 issuer 在上传包中根本不存在；
2. **交叉签发选链错误**：存在同名（subject DN 相同）但密钥不同、或同一公钥被不同根交叉签发的多张证书，需要**验签后区分**，且一条候选链失败不能阻止其他链被枚举。

全部计算在本机离线完成，不发起任何网络请求，不检查吊销（CRL/OCSP）与证书用途（EKU）。

## 诊断范围与规则

- 输入：1 张客户端证书（leaf）+ 1 个无序中间证书 PEM 包 + 1 张独立指定的受信根 PEM；
  三类输入去重后**总计最多 12 张**证书。
- 签名策略：**仅支持 RSA PKCS#1 v1.5 / SHA-256**（OID `1.2.840.113549.1.1.11`），其他算法在全局提示与逐链结果中标为不支持。
- 从叶子出发 DFS 枚举**所有无环候选路径**（含环时只记录无环前缀，保证终止；有枚举上限保护）。
- 同名签发者必须先验证签名：同 DN 但验签失败的证书不会进入任何链，并在「同名签发者歧义」专区列出。
- 对每条候选链独立检查，任一链失败不影响其他链：
  - 每张证书在给定校验时间的有效期（notBefore 含、notAfter 不含）；
  - 每个签发者 `BasicConstraints cA=TRUE`；
  - `KeyUsage` 扩展**存在时**必须包含 `keyCertSign`（不存在不强制）；
  - 每个签发者的 `pathLenConstraint`（RFC 5280：只统计其下方非自颁发的中间 CA；终端实体叶子与自颁发中间证书不占 pathLen）；
  - 链必须终止于独立指定的受信根（根的自签名同样验证）。
- 输出：存在通过链时展示第一条通过的链；全部失败时逐条列出候选链、失败位置（链内下标）、错误码与原因；缺失签发者单独专区列出（含「同名但验签失败」明细）。

## 快速开始（Docker Compose）

```bash
docker compose up --build -d
# 浏览器入口（nginx 网关，轮询两个 Web 进程 web1/web2）
open http://127.0.0.1:8080/        # Linux 可改用 xdg-open
```

页面上点击内置示例 `cross-sign` / `all-fail` 即可自动载入 PEM 与校验时间，直接点「开始诊断」。
容器以非 root 运行，只读根文件系统、丢弃 Linux capabilities、`no-new-privileges`，端口仅绑定回环地址。

停止：`docker compose down`

### 进程拓扑与在途正文预算

```
浏览器 ──► gateway(nginx:8080, 关闭请求缓冲)
              ├── web1 (uvicorn, WORKER_NAME=web1)
              └── web2 (uvicorn, WORKER_NAME=web2)
                    └── 共享命名卷 mtls-data:/data
                          ├── budget/budget.db     # SQLite 预算与 worker 心跳表
                          ├── budget/liveness/     # 每进程心跳文件（含实例 token）
                          └── staging/<worker>/<请求>/  # 各请求的上传临时文件
```

两级字节限额（均按**实际从套接字流式读到的字节**计数，绝不信任 `Content-Length`）：

| 限额 | 默认值 | 超限行为 | 计数范围 |
| --- | --- | --- | --- |
| 单请求 | 2 MiB（`PER_REQUEST_LIMIT`） | **413** | 完整 multipart 正文：PEM、未知字段、表单字段与 boundary 等开销全部计入 |
| 全站共享在途预算 | 4 MiB（`TOTAL_BUDGET`，两个进程共用） | **503 + Retry-After**，立即拒绝、不排队 | 所有处于接收/诊断中的请求正文之和 |

实现要点：

- 路由不使用框架的 `UploadFile`（它会先整包缓冲），而是直接驱动 `python-multipart` 的 push 解析器；ASGI 每收到一个 64 KiB 数据块，先查 2 MiB 单请求上限，再向 SQLite 申请共享预算，**申请成功后该块才进入解析器**，部件载荷逐块写入 `/data/staging` 下的临时文件，内存中从不保留整包正文。
- 每次申请都是一个立即提交的 SQLite 短事务（WAL + busy timeout），**接收正文与运行诊断期间不持有任何数据库写锁**。
- 预算在「诊断结束且全部上传临时文件关闭/删除」之后才归还；成功、坏 PEM、multipart 解析失败、413、503、客户端断连六条路径全部在 `finally` 中清理，无一例外。
- 每个进程启动时注册 worker 并每 5 秒刷新共享卷上的心跳文件；后台 reaper 每 10 秒扫描一次，发现心跳缺失或超过 30 秒（`STALE_AFTER_SECONDS`）未刷新的死亡进程，就在一个事务内删除其全部预算占用，并按 worker 命名空间清理其暂存目录、归还字节。存活进程的请求有独立命名空间，绝不会被误清。
- 诊断规则（含去重后 12 张证书上限）完全不变；拒绝页（413/503/400）只显示拒绝原因，不残留任何旧诊断结论，所有响应带 `Cache-Control: no-store`，其后的合法上传照常可用。


## 本地直接运行

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# 默认数据目录 /data；本地运行可指向可写目录
export APP_DATA_DIR=./.local-data
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

两个本地进程共用同一数据目录即可复现 Compose 的跨进程预算协调（分别设置不同的 `WORKER_NAME`，`BUDGET_DB`/`STAGING_DIR` 指向同一路径）。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 浏览器上传页面 |
| POST | `/diagnose` | 流式 multipart 表单：`leaf`、`intermediates`、`root`、`validation_time`（ISO 8601，无时区按 UTC），返回 HTML 结果页；413/503/400 返回带拒绝原因的上传页 |
| POST | `/api/diagnose` | 同入参，返回 JSON 诊断结果；413/503/400 返回 `{"error", "code"}` |
| GET | `/api/examples/{name}` | 取内置示例的 manifest 与 PEM 文本 |
| GET | `/examples/{name}` | 303 跳转并由前端自动填充示例 |

状态码：`200` 诊断完成；`400` 坏 PEM / 证书规则不满足 / multipart 格式错误；`413` 单请求正文超过 2 MiB；`503` 共享 4 MiB 在途预算不足（带 `Retry-After`，不排队）。

## 内置示例

由 `scripts/generate_examples.py` 离线生成（一次性 RSA-2048 临时密钥）：

- **cross-sign**：`Intermediate CA X` 的同一公钥被 Root A / Root B 交叉签发，另含一张同 DN 不同密钥的陈旧证书；Root B 被放进中间包但不是受信根。预期两条候选链，一条通过、一条因终止于不受信根而失败。
- **all-fail**：默认叶子触发 pathLen 违规；替换 `alt-leaf-*.pem` 可分别复现签发者过期、KeyUsage 缺 keyCertSign、缺失签发者三种失败。

重新生成：`python3 scripts/generate_examples.py`

## 测试

```bash
pip install -r requirements.txt
python3 -m pytest -q
```

覆盖：简单链通过、中间证书缺失、交叉签发同名验签区分、不因首条失败中止枚举、有效期边界、pathLen 与自颁发豁免、KeyUsage、非 CA 签发、签名算法白名单、环终止、12 张上限、去重、受信根自签名检查、Web/API 端到端；以及流式摄取专项（`tests/test_budget_ingest.py`）：

- 单请求 2 MiB 上限（multipart 开销、未知字段同样计入）→ 413 且暂存/预算立即清理；
- 伪造的小 `Content-Length` 不能绕过按实际字节执行的上限；
- 共享 4 MiB 预算耗尽 → 503 不排队、不影响其他请求的预留，释放后后续合法上传恢复；
- 413 优先于 503；坏 PEM、malformed multipart、客户端中途断连均释放预算且无临时文件残留；
- 大字段全程分块落盘（磁盘文件始终不超过一个数据块的量级），不整包缓冲；
- 死亡 worker 的暂存与预算被存活进程自动回收，存活 worker 的请求绝不被误清；
- HTML 拒绝页显示具体原因、不残留旧结论。

## 目录结构

```
app/
  diagnostics.py        # 核心：PEM 解析、建图、全路径 DFS、逐链约束校验（规则未改动）
  budget.py             # SQLite 共享字节预算、worker 心跳与死亡进程回收
  ingest.py             # 流式 multipart 解析：逐块占预算、逐块落临时文件、全路径清理
  main.py               # FastAPI 路由（HTML + JSON API，统一流式管线）
  templates/            # Jinja2 页面（拒绝原因横幅 + 限额说明）
  static/               # CSS 与示例载入脚本
  examples/             # 内置交叉签发/全失败示例 PEM
scripts/generate_examples.py
tests/
Dockerfile, docker-compose.yml, nginx.conf, requirements.txt
```
