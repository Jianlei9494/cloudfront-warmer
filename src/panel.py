"""cf-warmer 网页面板（Lambda Function URL 后端）。

由 build_template.py 把 panel.html 注入 PANEL_HTML 后，经安装器写入面板 Lambda。
路由：
  GET  /                 面板页面
  POST /api/login        口令登录，返回会话令牌
  GET  /api/config       区域与部署状态
  POST /api/precheck     HEAD 预检，估算流量
  POST /api/warm         执行预热（扇出到各区域 worker Lambda）
  GET  /api/history      最近的预热记录
  GET  /api/history/<id> 单次预热的完整结果
  GET  /api/schedules    预定任务列表
  POST /api/schedules    新建单次预定
  DELETE /api/schedules/<id> 取消待执行的预定
  GET  /api/distributions 本账号的 CloudFront 分发
  POST /api/dir/preview   列出目录文件并预览
  POST /api/dir/jobs      新建目录任务（立即或预定）
  GET  /api/dir/jobs[/id] 目录任务列表 / 详情
  DELETE /api/dir/jobs/<id> 取消目录任务
另：EventBridge 每分钟直接调用一次，执行到点的预定任务，并分批推进目录任务。
"""

import base64
import fnmatch
import re
import hashlib
import hmac
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config

PANEL_HTML = "__PANEL_HTML__"

FUNCTION_NAME = "cf-warmer"
TABLE = os.environ.get("TABLE", "")
REGIONS = [r.strip() for r in os.environ.get("REGIONS", "").split(",") if r.strip()]
ALLOWED_HOSTS = [h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()]
# 客户可选的自我约束，0 = 不限（默认）
MAX_OBJECT_MB = int(os.environ.get("MAX_OBJECT_MB", "0"))
MAX_DIR_FILES = int(os.environ.get("MAX_DIR_FILES", "0"))
# 物理上限：函数 URL 请求体最大 6 MB，约可容纳这么多地址
MAX_URLS = 20000
# 同步执行的门槛：超过就自动转后台任务（面板函数一次最多运行 15 分钟）
SYNC_MAX_URLS = 20
MAX_JOBS = 300
WORKER_TIMEOUT = int(os.environ.get("WORKER_TIMEOUT", "900"))
HOME_REGION = os.environ.get("AWS_REGION", "us-east-1")
PANEL_ROLE_ARN = os.environ.get("PANEL_ROLE_ARN", "")
SESSION_SECONDS = 12 * 3600
HISTORY_DAYS = 90
DEFAULT_ENCODING = "gzip, deflate, br"

_ddb = boto3.client("dynamodb")
_lambda_cfg = Config(read_timeout=905, connect_timeout=10, retries={"max_attempts": 1})
_clients = {}
_auth_cache = {}


def _client(region):
    if region not in _clients:
        _clients[region] = boto3.client("lambda", region_name=region, config=_lambda_cfg)
    return _clients[region]


# ─────────────────────────── HTTP 工具 ───────────────────────────

def _resp(status, body, ctype="application/json; charset=utf-8"):
    if not isinstance(body, str):
        body = json.dumps(body, ensure_ascii=False)
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": ctype,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; "
                                       "style-src 'unsafe-inline'; connect-src 'self'; img-src data:; "
                                       "frame-ancestors 'none'",
        },
        "body": body,
    }


def _err(status, msg):
    return _resp(status, {"error": msg})


def _body(event):
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return None


# ─────────────────────────── 鉴权 ───────────────────────────

def _auth_record():
    if "rec" not in _auth_cache or time.time() - _auth_cache.get("at", 0) > 60:
        item = _ddb.get_item(TableName=TABLE, Key={"pk": {"S": "config"}, "sk": {"S": "auth"}},
                             ConsistentRead=True).get("Item")
        if not item:
            raise RuntimeError("口令未初始化，请检查 CloudFormation 部署是否成功")
        _auth_cache["rec"] = (item["salt"]["S"], item["hash"]["S"])
        _auth_cache["at"] = time.time()
    return _auth_cache["rec"]


def _sign(exp, key):
    return hmac.new(bytes.fromhex(key), str(exp).encode(), hashlib.sha256).hexdigest()


def _login(password):
    salt, want = _auth_record()
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200000).hex()
    if not hmac.compare_digest(got, want):
        time.sleep(1)  # 拖慢暴力尝试
        return None
    exp = int(time.time()) + SESSION_SECONDS
    return f"{exp}.{_sign(exp, want)}"


def _authed(event):
    h = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    tok = h.get("authorization", "")
    if not tok.startswith("Bearer "):
        return False
    exp, _, sig = tok[7:].partition(".")
    if not exp.isdigit() or int(exp) < time.time():
        return False
    _, key = _auth_record()
    return hmac.compare_digest(sig, _sign(int(exp), key))


# ─────────────────────────── 校验 ───────────────────────────

def _check_url(u):
    if not isinstance(u, str) or len(u) > 2048:
        return "URL 无效"
    p = urllib.parse.urlsplit(u.strip())
    if p.scheme.lower() != "https" or not p.hostname:
        return "只支持完整的 https:// URL"
    if "*" in p.path:
        return "不支持通配符，只能预热具体对象"
    if ALLOWED_HOSTS and p.hostname.lower() not in ALLOWED_HOSTS:
        return "域名不在允许列表中（部署参数 AllowedHosts）"
    return None


def _parse_urls(raw):
    if not isinstance(raw, list):
        return None, "urls 必须是列表"
    urls, seen = [], set()
    for u in raw:
        u = (u or "").strip() if isinstance(u, str) else u
        if not u:
            continue
        e = _check_url(u)
        if e:
            return None, f"{u}：{e}"
        if u not in seen:
            seen.add(u)
            urls.append(u)
    if not urls:
        return None, "请至少填一个 URL"
    if len(urls) > MAX_URLS:
        return None, f"一次提交的地址太多（{len(urls)} 个，单次请求最多约 {MAX_URLS} 个），请分几次提交或改用「按目录」"
    return urls, None


def _parse_headers(raw):
    out = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        k, sep, v = line.partition(":")
        if not sep or not k.strip() or any(c in k for c in " \t\r\n"):
            raise ValueError(f"请求头格式应为「名称: 值」：{line}")
        out[k.strip()] = v.strip()
    return out


# ─────────────────────────── 预检 ───────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def _head(url, headers):
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "cf-warmer/1.0", **headers})
    try:
        with _OPENER.open(req, timeout=15) as r:
            h = r.headers
            if not (h.get("X-Amz-Cf-Pop") or "cloudfront" in (h.get("Via") or "").lower()):
                return {"url": url, "status": r.status, "size": None,
                        "error": "不是 CloudFront 分发的地址（响应头没有 CloudFront 标识），预热不会生效"}
            cl = h.get("Content-Length")
            return {"url": url, "status": r.status, "size": int(cl) if cl and cl.isdigit() else None}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "size": None,
                "error": f"返回 HTTP {e.code}，重定向或错误响应不会被预热"}
    except Exception as e:  # noqa: BLE001
        return {"url": url, "status": None, "size": None, "error": f"无法访问：{e}"}


# ── 各区域实测下载速度（字节 / 秒），用来提示「可能超时」，不用来拦截 ──
_speed_cache = {}
SPEED_MIN_BYTES = 2 * 1024 * 1024   # 小文件的耗时主要是连接延迟，不计入速度


def _speeds():
    if time.time() - _speed_cache.get("at", 0) < 60:
        return _speed_cache["v"]
    v = {}
    try:
        it = _ddb.get_item(TableName=TABLE, Key={"pk": {"S": "config"}, "sk": {"S": "speed"}}).get("Item")
        if it:
            v = json.loads(it["v"]["S"])
    except Exception as e:  # noqa: BLE001 —— 读不到只是不给提示
        print("read speed failed:", repr(e))
    _speed_cache.update(v=v, at=time.time())
    return v


def _speed_update(results):
    samples = {}
    for x in results:
        b, ms = int(x.get("bytes") or 0), int(x.get("elapsed_ms") or 0)
        if x.get("ok") and b >= SPEED_MIN_BYTES and ms > 0:
            samples.setdefault(x["region"], []).append(b / (ms / 1000))
    if not samples:
        return
    v = dict(_speeds())
    for r, xs in samples.items():
        cur = sorted(xs)[len(xs) // 2]
        v[r] = cur if r not in v else 0.5 * v[r] + 0.5 * cur
    try:
        _ddb.put_item(TableName=TABLE, Item={"pk": {"S": "config"}, "sk": {"S": "speed"},
                                             "v": {"S": json.dumps(v)}})
        _speed_cache.update(v=v, at=time.time())
    except Exception as e:  # noqa: BLE001
        print("save speed failed:", repr(e))


def _eta_warn(size, regions=None):
    """按实测速度估算最慢区域的下载用时；可能超过预热函数上限时返回提示文字。"""
    if not size:
        return None
    sp = _speeds()
    known = [sp[r] for r in (regions or REGIONS) if r in sp and sp[r] > 0]
    limit = WORKER_TIMEOUT * 0.9
    if known:
        eta = size / min(known)
        if eta > limit:
            return (f"按以往实测速度，最慢的区域约需 {eta / 60:.0f} 分钟，可能超过单次 {WORKER_TIMEOUT // 60} 分钟上限而下载不完；"
                    "可调大预热函数内存（部署参数 WorkerMemoryMB）后重试")
    elif size > 2 * 1024 ** 3:
        return f"文件较大，可能在 {WORKER_TIMEOUT // 60} 分钟内下载不完（还没有实测速度可参考）"
    return None


def _precheck(urls, headers):
    with ThreadPoolExecutor(16) as t:
        rows = list(t.map(lambda u: _head(u, headers), urls))
    for r in rows:
        if r.get("error"):
            r["ok"] = False
        elif MAX_OBJECT_MB and r["size"] is not None and r["size"] > MAX_OBJECT_MB * 1024 * 1024:
            r["ok"] = False
            r["error"] = f"超过你设置的单个对象上限 {MAX_OBJECT_MB} MB（部署参数 MaxObjectMB）"
        else:
            r["ok"] = True
            w = _eta_warn(r["size"])
            if w:
                r["warn"] = w
    return rows


# ─────────────────────────── 预热 ───────────────────────────

def _invoke(region, url, enc, headers, verify):
    h = dict(headers)
    h["Accept-Encoding"] = enc
    try:
        resp = _client(region).invoke(FunctionName=FUNCTION_NAME,
                                      Payload=json.dumps({"url": url, "headers": h, "verify": verify}).encode())
        body = json.loads(resp["Payload"].read() or b"{}")
        if resp.get("FunctionError"):
            body = {"ok": False, "error": f"Lambda 执行出错：{body.get('errorMessage', '')}"}
    except Exception as e:  # noqa: BLE001 —— 单点失败如实记录
        name = type(e).__name__
        hint = ("该区域未部署" if "ResourceNotFound" in name
                else "该区域未在账号中启用" if "UnrecognizedClient" in str(e) else name)
        body = {"ok": False, "error": f"调用失败：{hint}"}
    body.update({"url": url, "region": region, "encoding": enc})
    return body


def _validate(req):
    """校验并规范化预热请求。返回 (规范化请求, None) 或 (None, (状态码, 错误文本))。"""
    urls, e = _parse_urls(req.get("urls"))
    if e:
        return None, (400, e)
    raw_headers = req.get("headers") or ""
    if not isinstance(raw_headers, str) or len(raw_headers) > 8192:
        return None, (400, "请求头格式不正确")
    try:
        _parse_headers(raw_headers)
    except ValueError as x:
        return None, (400, str(x))
    mode = req.get("mode", "full")
    if mode not in ("full", "economy"):
        return None, (400, "预热范围只能是 full 或 economy")
    eco = req.get("economyRegion") or "us-east-1"
    if mode == "economy" and eco not in REGIONS:
        return None, (400, "经济模式的区域不在已部署区域中")
    encs = [x for x in (req.get("encodings") or [DEFAULT_ENCODING]) if isinstance(x, str) and x.strip()][:4]
    return {"urls": urls, "headers": raw_headers, "mode": mode, "economyRegion": eco,
            "encodings": encs or [DEFAULT_ENCODING], "verify": bool(req.get("verify"))}, None


def _warm_core(req, trigger="manual", save=True):
    """执行一次预热。返回 (HTTP 状态码, 响应体 dict)。手动预热与预定执行共用。"""
    v, e = _validate(req)
    if e:
        return e[0], {"error": e[1]}
    headers = _parse_headers(v["headers"])
    mode = v["mode"]
    if mode == "economy":
        regions = [v["economyRegion"]]
    else:
        # 只用已就绪的区域（如账号未启用 me-central-1，就不每次都报一格失败）。
        status = _ready_map()
        regions = [r for r in REGIONS if status.get(r)]
        if not regions:
            return 503, {"error": "没有已就绪的区域，请检查 CloudFormation 部署输出"}
    encs, verify = v["encodings"], v["verify"]

    # 预热前再预检一次（不信任前端；预定任务执行时也会重新检查），只热通过预检的 URL。
    pre = _precheck(v["urls"], headers)
    good = [p["url"] for p in pre if p["ok"]]
    if not good:
        return 200, {"precheck": pre, "results": [], "error": "没有通过预检的 URL"}
    jobs = [(r, u, x) for u in good for r in regions for x in encs]
    if len(jobs) > MAX_JOBS:
        return 400, {"error": f"本次共 {len(jobs)} 次下载，超过上限 {MAX_JOBS}，请减少 URL、区域或编码"}

    t0 = time.time()
    with ThreadPoolExecutor(32) as t:
        results = list(t.map(lambda j: _invoke(j[0], j[1], j[2], headers, verify), jobs))

    summary = {
        "id": uuid.uuid4().hex[:12],
        "at": int(t0),
        "trigger": trigger,
        "mode": mode,
        "regions": regions,
        "encodings": encs,
        "urls": good,
        "skipped": [p for p in pre if not p["ok"]],
        "ok": sum(1 for x in results if x.get("ok")),
        "total": len(results),
        "bytes": sum(int(x.get("bytes") or 0) for x in results),
        "seconds": round(time.time() - t0, 1),
    }
    _speed_update(results)
    if save:
        _save(summary, results)
    return 200, {"summary": summary, "precheck": pre, "results": results}


def _warm(req):
    v, e = _validate(req)
    if e:
        return _err(*e)
    if _is_large(v):
        return _urls_job(v, int(time.time()))
    st, body = _warm_core(req, "manual")
    return _resp(st, body)


# ─────────────────────────── 预定执行（单次） ───────────────────────────
#
# 预定 = 一条 pk="sched" 的记录。EventBridge 每分钟唤醒本函数一次（_sched_tick），
# 到点的任务用条件更新「pending → running」认领，保证同一任务只执行一次；
# 执行结果照常写进预热记录（trigger=scheduled）。

SCHED_MAX_DAYS = 30
SCHED_MAX_PENDING = 50
SCHED_STUCK_SECONDS = 1200  # 认领后超过这么久仍是 running，视为执行被中断


def _sched_view(it):
    req = json.loads(it["req"]["S"])
    return {
        "id": it["id"]["S"],
        "at": int(it["at"]["N"]),
        "status": it["status"]["S"],
        "mode": req.get("mode"),
        "urls": req.get("urls", []),
        "created": int(it["created"]["N"]),
        "run_id": it.get("run_id", {}).get("S"),
        "ok": int(it["ok"]["N"]) if "ok" in it else None,
        "total": int(it["total"]["N"]) if "total" in it else None,
        "error": it.get("error", {}).get("S"),
    }


def _sched_items():
    out, kw = [], {}
    while True:
        r = _ddb.query(TableName=TABLE, KeyConditionExpression="pk = :p",
                       ExpressionAttributeValues={":p": {"S": "sched"}}, ConsistentRead=True, **kw)
        out += r.get("Items", [])
        if "LastEvaluatedKey" not in r:
            return out
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def _sched_create(b):
    v, e = _validate(b)
    if e:
        return _err(*e)
    at = b.get("at")
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        return _err(400, "请选择预定时间")
    at, now = int(at), int(time.time())
    if at < now + 60:
        return _err(400, "预定时间至少要在 1 分钟之后")
    if at > now + SCHED_MAX_DAYS * 86400:
        return _err(400, f"预定时间不能超过 {SCHED_MAX_DAYS} 天")
    if sum(1 for it in _sched_items() if it["status"]["S"] == "pending") >= SCHED_MAX_PENDING:
        return _err(400, f"待执行的预定最多 {SCHED_MAX_PENDING} 个，请先取消一些")
    if _is_large(v):
        return _urls_job(v, at)  # 地址多：预定执行也走后台任务（start_at = 预定时间）
    sid = uuid.uuid4().hex[:12]
    item = {
        "pk": {"S": "sched"}, "sk": {"S": sid}, "id": {"S": sid},
        "at": {"N": str(at)}, "status": {"S": "pending"}, "created": {"N": str(now)},
        "req": {"S": json.dumps(v, ensure_ascii=False)},
        "ttl": {"N": str(at + HISTORY_DAYS * 86400)},
    }
    _ddb.put_item(TableName=TABLE, Item=item)
    return _resp(200, {"schedule": _sched_view(item)})


def _sched_list():
    items = [_sched_view(it) for it in _sched_items()]
    pending = sorted([x for x in items if x["status"] in ("pending", "running")], key=lambda x: x["at"])
    done = sorted([x for x in items if x["status"] not in ("pending", "running")], key=lambda x: -x["at"])
    return _resp(200, {"schedules": pending + done[:20]})


def _sched_cancel(sid):
    if not sid.isalnum() or len(sid) > 32:
        return _err(400, "预定 ID 无效")
    try:
        _ddb.update_item(TableName=TABLE, Key={"pk": {"S": "sched"}, "sk": {"S": sid}},
                         UpdateExpression="SET #s = :c",
                         ConditionExpression="#s = :p",
                         ExpressionAttributeNames={"#s": "status"},
                         ExpressionAttributeValues={":c": {"S": "cancelled"}, ":p": {"S": "pending"}})
    except _ddb.exceptions.ConditionalCheckFailedException:
        return _err(409, "只能取消待执行的预定（可能已经开始执行或已取消）")
    return _resp(200, {"ok": True})


def _sched_set(sid, expect, values):
    names = {"#s": "status"}
    vals = {":e": {"S": expect}}
    sets = []
    for i, (k, v) in enumerate(values.items()):
        names[f"#k{i}"] = k
        vals[f":v{i}"] = v
        sets.append(f"#k{i} = :v{i}")
    _ddb.update_item(TableName=TABLE, Key={"pk": {"S": "sched"}, "sk": {"S": sid}},
                     UpdateExpression="SET " + ", ".join(sets), ConditionExpression="#s = :e",
                     ExpressionAttributeNames=names, ExpressionAttributeValues=vals)


def _sched_tick(context):
    now = int(time.time())
    items = _sched_items()
    for it in items:
        if it["status"]["S"] == "running" and int(it.get("claimed", {}).get("N", "0")) < now - SCHED_STUCK_SECONDS:
            try:
                _sched_set(it["id"]["S"], "running", {"status": {"S": "failed"},
                                                       "error": {"S": "执行被中断（超时或函数异常），请重新预定"}})
            except _ddb.exceptions.ConditionalCheckFailedException:
                pass
    due = sorted([it for it in items if it["status"]["S"] == "pending" and int(it["at"]["N"]) <= now],
                 key=lambda it: int(it["at"]["N"]))
    ran = 0
    for it in due:
        if context is not None and context.get_remaining_time_in_millis() < 300_000:
            break  # 剩余时间不够，留给下一分钟
        sid = it["id"]["S"]
        try:
            _sched_set(sid, "pending", {"status": {"S": "running"}, "claimed": {"N": str(int(time.time()))}})
        except _ddb.exceptions.ConditionalCheckFailedException:
            continue  # 已被取消或被另一次唤醒认领
        try:
            st, body = _warm_core(json.loads(it["req"]["S"]), "scheduled")
            if "summary" in body:
                s = body["summary"]
                _sched_set(sid, "running", {"status": {"S": "done"}, "run_id": {"S": s["id"]},
                                            "ok": {"N": str(s["ok"])}, "total": {"N": str(s["total"])}})
            else:
                _sched_set(sid, "running", {"status": {"S": "failed"},
                                            "error": {"S": str(body.get("error") or f"HTTP {st}")[:500]}})
        except Exception as x:  # noqa: BLE001 —— 单个任务失败不影响其他任务
            print("scheduled run failed:", sid, repr(x))
            try:
                _sched_set(sid, "running", {"status": {"S": "failed"}, "error": {"S": f"执行出错：{type(x).__name__}"}})
            except Exception:  # noqa: BLE001
                pass
        ran += 1
    return {"due": len(due), "ran": ran}


# ─────────────────────────── 目录预热 ───────────────────────────
#
# 流程：选分发 + 目录 → 读分发配置找到该目录对应的 S3 源站 → 列出桶内文件
# → 按 OriginPath 换算成 CloudFront 地址 → 预览（文件数 / 大小 / 跳过原因）
# → 建目录任务（pk="dir"），由每分钟的定时唤醒分批（每批 DIR_BATCH 个文件）执行。
# 只读权限：cloudfront:ListDistributions / GetDistributionConfig、s3:ListBucket。

DIR_MAX_ACTIVE = 50              # 同时待执行 / 执行中的后台任务上限（防误操作堆积，不限制单个任务大小）
DIR_MAX_FAILURES_KEPT = 100      # 任务里保留的失败明细条数
FILES_CHUNK = 1000               # 文件清单分块存储，每块这么多个地址（单条记录 400 KB 上限）
BATCH_INVOKES = 600              # 每批最多同时发出的预热调用数（文件 × 区域 × 压缩格式）
BATCH_MAX_FILES = 200
LEASE_SECONDS = 880              # 面板函数一次最多运行 900 秒
POLL_SECONDS = 60                # 一次唤醒里最多等当前批多久，等不到就交给下一分钟
EVENT_MAX_AGE = 1200             # 异步调用最多排队 20 分钟（安装器给预热函数设置的同一值）
BATCH_DEADLINE = EVENT_MAX_AGE + WORKER_TIMEOUT + 60   # 超过还没回报的调用判为超时
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
_S3_HOST = re.compile(r"^(?P<b>[a-z0-9][a-z0-9.\-]*?)\.s3(?:-website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$")
_cf = boto3.client("cloudfront", region_name="us-east-1")
_s3 = boto3.client("s3")
_async_clients = {}


def _dispatch(region, payload):
    """异步调用预热函数（结果由预热函数写回本表）。"""
    if region not in _async_clients:
        _async_clients[region] = boto3.client("lambda", region_name=region,
                                              config=Config(connect_timeout=10, read_timeout=30,
                                                            retries={"max_attempts": 3}))
    _async_clients[region].invoke(FunctionName=FUNCTION_NAME, InvocationType="Event",
                                  Payload=json.dumps(payload).encode())


def _dists():
    out, kw = [], {}
    while True:
        r = _cf.list_distributions(**kw).get("DistributionList", {})
        for d in r.get("Items", []) or []:
            out.append({"id": d["Id"], "domain": d["DomainName"], "enabled": d.get("Enabled", False),
                        "aliases": (d.get("Aliases") or {}).get("Items", []) or [],
                        "comment": d.get("Comment", "")})
        if not r.get("IsTruncated"):
            return out
        kw["Marker"] = r["NextMarker"]


def _norm_dir(d):
    if not isinstance(d, str) or not d.strip() or len(d) > 1024:
        return None, "请填写目录，如 /static/v2/"
    d = d.strip()
    if not d.startswith("/"):
        d = "/" + d
    if any(c in d for c in "*?#\\") or "/../" in d + "/" or "/./" in d + "/":
        return None, "目录里不能有通配符、?、#、反斜杠或 ../"
    if not d.endswith("/"):
        d += "/"
    return d, None


def _primary_origin(cfg, target_id):
    """缓存行为指向源站组时，取主源站。"""
    for g in (cfg.get("OriginGroups") or {}).get("Items", []) or []:
        if g["Id"] == target_id:
            m = g["Members"]["Items"]
            return m[0]["OriginId"] if m else None
    return target_id


def _behavior_origin(cfg, viewer_path):
    for b in (cfg.get("CacheBehaviors") or {}).get("Items", []) or []:
        if fnmatch.fnmatchcase(viewer_path, "/" + b["PathPattern"].lstrip("/")):
            return _primary_origin(cfg, b["TargetOriginId"])
    return _primary_origin(cfg, cfg["DefaultCacheBehavior"]["TargetOriginId"])


def _s3_origin(cfg, origin_id):
    for o in cfg["Origins"]["Items"]:
        if o["Id"] == origin_id:
            m = _S3_HOST.match(o["DomainName"].lower())
            if not m:
                return None, None, "该目录的源站不是 S3（" + o["DomainName"] + "），无法列出文件"
            return m.group("b"), (o.get("OriginPath") or "").strip("/"), None
    return None, None, "找不到该目录对应的源站"


def _role_arn():
    """面板自己的角色 ARN（写进给桶主人的策略里）。优先取部署时注入的值，取不到再从当前身份推出来。"""
    if PANEL_ROLE_ARN:
        return PANEL_ROLE_ARN
    try:
        arn = boto3.client("sts").get_caller_identity()["Arn"]   # arn:aws:sts::ACCT:assumed-role/ROLE/SESSION
        part, acct, rest = arn.split(":")[1], arn.split(":")[4], arn.split(":", 5)[5]
        if rest.startswith("assumed-role/"):
            return f"arn:{part}:iam::{acct}:role/{rest.split('/')[1]}"
    except Exception as e:  # noqa: BLE001
        print("resolve role arn failed:", repr(e))
    return None


def _list_policy(bucket, prefix):
    """存储桶在其他账号时，桶主人需要加的桶策略（只授列举，不授读写）。"""
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Sid": "AllowCfWarmerList", "Effect": "Allow",
        "Principal": {"AWS": _role_arn() or "<cf-warmer 面板角色 ARN>"},
        "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}",
        **({"Condition": {"StringLike": {"s3:prefix": [prefix + "*"]}}} if prefix else {})}]},
        ensure_ascii=False, indent=2)


def _dir_source(b, d):
    """解析「访问域名 + 存储桶 + 源站路径」。返回 (dict, None) 或 (None, (状态码, 错误))。
    - 选分发：读本账号分发配置，按缓存行为找到该目录的 S3 源站
    - 手动填写：分发或存储桶在其他账号时，由客户直接给出（不做缓存行为过滤）"""
    m = b.get("manual")
    if m:
        if not isinstance(m, dict):
            return None, (400, "手动填写的内容格式不正确")
        host = re.sub(r"^https?://", "", (m.get("host") or "").strip(), flags=re.I).split("/")[0].lower()
        bucket = re.sub(r"^(https?|s3)://", "", (m.get("bucket") or "").strip(), flags=re.I).split("/")[0].lower()
        hm = _S3_HOST.match(bucket)   # 允许直接粘贴 CloudFront 控制台里的「源域」
        if hm:
            bucket = hm.group("b")
        opath = (m.get("originPath") or "").strip().strip("/")
        if not _HOSTNAME.match(host):
            return None, (400, "访问域名格式不正确（只填域名，如 cdn.example.com，不要带 https:// 或路径）")
        e = _check_url(f"https://{host}/x")
        if e:
            return None, (400, f"访问域名：{e}")
        if not _BUCKET.match(bucket):
            return None, (400, "请填写正确的 S3 存储桶名称（只要名称，不要 s3:// 或网址）")
        if any(c in opath for c in "*?#\\") or ".." in opath.split("/"):
            return None, (400, "源站路径格式不正确")
        return {"distribution": None, "host": host, "bucket": bucket, "opath": opath, "cfg": None,
                "origin_id": None}, None

    dist_id = b.get("distribution")
    if not isinstance(dist_id, str) or not re.fullmatch(r"[A-Z0-9]{8,20}", dist_id or ""):
        return None, (400, "请选择 CloudFront 分发")
    try:
        cfg = _cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    except _cf.exceptions.NoSuchDistribution:
        return None, (404, "分发不存在")
    hosts = list((cfg.get("Aliases") or {}).get("Items", []) or [])
    try:
        hosts.append(_cf.get_distribution(Id=dist_id)["Distribution"]["DomainName"])
    except Exception:  # noqa: BLE001
        pass
    host = b.get("host") or (hosts[0] if hosts else None)
    if host not in hosts:
        return None, (400, "访问域名不属于该分发")
    if ALLOWED_HOSTS and host.lower() not in ALLOWED_HOSTS:
        return None, (400, "域名不在允许列表中（部署参数 AllowedHosts）")
    origin_id = _behavior_origin(cfg, d + "x")
    bucket, opath, e = _s3_origin(cfg, origin_id)
    if e:
        return None, (400, e)
    return {"distribution": dist_id, "host": host, "bucket": bucket, "opath": opath, "cfg": cfg,
            "origin_id": origin_id}, None


def _dir_list(b, full=False):
    """列出目录下的文件。返回 (结果 dict, None) 或 (None, (状态码, 错误 或 错误 dict))。"""
    d, e = _norm_dir(b.get("dir"))
    if e:
        return None, (400, e)
    src, e = _dir_source(b, d)
    if e:
        return None, e
    host, bucket, opath, cfg, origin_id = src["host"], src["bucket"], src["opath"], src["cfg"], src["origin_id"]
    dist_id = src["distribution"]
    key_prefix = (opath + "/" if opath else "") + d.lstrip("/")
    strip = len(opath) + 1 if opath else 0

    files, skipped, total, kw, warns = [], [], 0, {}, 0
    limit = MAX_OBJECT_MB * 1024 * 1024 if MAX_OBJECT_MB else None
    try:
        while True:
            r = _s3.list_objects_v2(Bucket=bucket, Prefix=key_prefix, MaxKeys=1000, **kw)
            for o in r.get("Contents", []) or []:
                k = o["Key"]
                if k.endswith("/"):
                    continue  # 「文件夹」占位对象
                path = "/" + k[strip:]
                url = "https://" + host + urllib.parse.quote(path, safe="/~!$&'()+,;=:@-._")
                if cfg is not None and _behavior_origin(cfg, path) != origin_id:
                    skipped.append({"url": url, "reason": "该路径由其他源站提供"})
                elif limit and o["Size"] > limit:
                    skipped.append({"url": url, "size": o["Size"], "reason": f"超过你设置的单个对象上限 {MAX_OBJECT_MB} MB"})
                elif o["Size"] == 0:
                    skipped.append({"url": url, "size": 0, "reason": "空文件"})
                else:
                    w = _eta_warn(o["Size"])
                    files.append({"url": url, "size": o["Size"], **({"warn": w} if w else {})})
                    total += o["Size"]
                    warns += bool(w)
                if MAX_DIR_FILES and len(files) > MAX_DIR_FILES:
                    return None, (400, f"该目录下可预热的文件超过你设置的上限 {MAX_DIR_FILES} 个（部署参数 MaxDirFiles），请缩小目录范围")
            if not r.get("IsTruncated"):
                break
            kw["ContinuationToken"] = r["NextContinuationToken"]
            if _ctx.get("c") is not None and _ctx["c"].get_remaining_time_in_millis() < 60_000:
                return None, (400, f"目录太大，在时限内没能列完（已列出 {len(files)} 个文件），请缩小目录范围")
    except Exception as x:  # noqa: BLE001
        code = getattr(x, "response", {}).get("Error", {}).get("Code", type(x).__name__)
        if code in ("AccessDenied", "AllAccessDisabled"):
            return None, (403, {"error": f"没有权限列出存储桶 {bucket} 的文件。如果这个桶在其他 AWS 账号，"
                                         "请桶的主人在桶策略里加上下面这段（只允许列出文件名，不能读写文件），保存后重试",
                                "policy": _list_policy(bucket, key_prefix), "bucket": bucket})
        if code == "NoSuchBucket":
            return None, (400, f"存储桶 {bucket} 不存在")
        return None, (502, f"列出存储桶 {bucket} 失败：{code}")
    if not files:
        hint = "；如果源站路径填错了也会这样" if cfg is None else ""
        return None, (400, "该目录下没有可预热的文件" + (f"（跳过 {len(skipped)} 个）" if skipped else "") + hint)
    return {"distribution": dist_id, "host": host, "dir": d, "bucket": bucket, "originPath": opath,
            "manual": cfg is None,
            "files": files if full else files[:200], "file_count": len(files), "warn_count": warns,
            "total_bytes": total, "skipped": skipped[:200], "skipped_count": len(skipped)}, None


def _dir_err(e):
    st, body = e
    return _resp(st, body) if isinstance(body, dict) else _err(st, body)


def _dir_preview(b):
    res, e = _dir_list(b)
    if e:
        return _dir_err(e)
    first = res["files"][0]
    h = _head(first["url"], _parse_headers(b.get("headers") if isinstance(b.get("headers"), str) else ""))
    res["sample"] = {"url": first["url"], "ok": not h.get("error"), "status": h.get("status"), "error": h.get("error")}
    return _resp(200, res)


def _dir_view(it, full=False):
    g = lambda k, t="S", d=None: it[k][t] if k in it else d
    v = {"id": g("id"), "status": g("status"), "host": g("host"), "dir": g("dir"),
         "kind": g("kind", d="dir"), "label": g("label") or ((g("host") or "") + (g("dir") or "")),
         "start_at": int(g("start_at", "N", "0")), "created": int(g("created", "N", "0")),
         "finished": int(g("finished", "N", "0")) or None,
         "total": int(g("total", "N", "0")), "cursor": int(g("cursor", "N", "0")),
         "files_ok": int(g("files_ok", "N", "0")), "files_failed": int(g("files_failed", "N", "0")),
         "bytes": int(g("bytes", "N", "0")), "error": g("error"),
         "downloads": int(g("downloads", "N", "0")), "hits": int(g("hits", "N", "0")),
         "verify": bool(json.loads(g("req", d="{}")).get("verify")),
         "mode": json.loads(g("req", d="{}")).get("mode")}
    if full:
        v["failures"] = json.loads(g("failures", d="[]"))
    return v


_DIR_ATTRS = ["id", "status", "host", "dir", "kind", "label", "start_at", "created", "finished", "total", "cursor",
              "files_ok", "files_failed", "bytes", "downloads", "hits", "error", "req", "failures", "lease_until"]


def _dir_items():
    attrs = _DIR_ATTRS
    names = {f"#a{i}": a for i, a in enumerate(attrs)}
    out, kw = [], {}
    while True:
        r = _ddb.query(TableName=TABLE, KeyConditionExpression="pk = :p",
                       ExpressionAttributeValues={":p": {"S": "dir"}}, ConsistentRead=True,
                       ProjectionExpression=", ".join(names), ExpressionAttributeNames=names, **kw)
        out += r.get("Items", [])
        if "LastEvaluatedKey" not in r:
            return out
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def _job_key(jid):
    return {"pk": {"S": "dir"}, "sk": {"S": jid}}


def _job_put_files(jid, urls, ttl):
    for i in range(0, len(urls), FILES_CHUNK):
        _ddb.put_item(TableName=TABLE, Item={
            "pk": {"S": "jobf#" + jid}, "sk": {"S": f"{i // FILES_CHUNK:06d}"},
            "urls": {"S": json.dumps(urls[i:i + FILES_CHUNK], ensure_ascii=False, separators=(",", ":"))},
            "ttl": {"N": str(ttl)}})


def _job_files(jid, start, count, cache):
    """读取清单里 [start, start+count) 的地址；cache 是本次唤醒内的分块缓存。"""
    out, i = [], start
    while len(out) < count:
        c = i // FILES_CHUNK
        if c not in cache:
            it = _ddb.get_item(TableName=TABLE, Key={"pk": {"S": "jobf#" + jid}, "sk": {"S": f"{c:06d}"}},
                               ConsistentRead=True).get("Item")
            cache[c] = json.loads(it["urls"]["S"]) if it else []
        chunk = cache[c]
        off = i - c * FILES_CHUNK
        if off >= len(chunk):
            break
        take = chunk[off:off + count - len(out)]
        out += take
        i += len(take)
    return out


def _job_create(urls, v, start, kind, label, host="", d=""):
    """建后台任务。v 是 _validate 规范化后的请求（取其中的模式 / 编码 / 请求头 / 复查）。"""
    now = int(time.time())
    if sum(1 for it in _dir_items() if it["status"]["S"] in ("pending", "running")) >= DIR_MAX_ACTIVE:
        return None, (400, f"同时待执行或执行中的后台任务最多 {DIR_MAX_ACTIVE} 个，请等前面的完成或取消")
    req = {k: v[k] for k in ("headers", "mode", "economyRegion", "encodings", "verify")}
    jid = uuid.uuid4().hex[:12]
    ttl = start + HISTORY_DAYS * 86400
    _job_put_files(jid, urls, ttl)
    item = {
        "pk": {"S": "dir"}, "sk": {"S": jid}, "id": {"S": jid}, "status": {"S": "pending"},
        "kind": {"S": kind}, "label": {"S": label}, "host": {"S": host}, "dir": {"S": d},
        "start_at": {"N": str(start)}, "created": {"N": str(now)},
        "total": {"N": str(len(urls))}, "cursor": {"N": "0"}, "batch": {"N": "0"},
        "files_ok": {"N": "0"}, "files_failed": {"N": "0"}, "bytes": {"N": "0"},
        "downloads": {"N": "0"}, "hits": {"N": "0"},
        "req": {"S": json.dumps(req, ensure_ascii=False)}, "failures": {"S": "[]"},
        "lease_until": {"N": "0"}, "ttl": {"N": str(ttl)},
    }
    _ddb.put_item(TableName=TABLE, Item=item)
    return item, None


def _parse_start(b):
    now = int(time.time())
    at = b.get("at")
    if at is None:
        return now, None
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        return None, "请选择预定时间"
    at = int(at)
    if at < now + 60:
        return None, "预定时间至少要在 1 分钟之后"
    if at > now + SCHED_MAX_DAYS * 86400:
        return None, f"预定时间不能超过 {SCHED_MAX_DAYS} 天"
    return at, None


def _is_large(v):
    n_reg = 1 if v["mode"] == "economy" else max(1, sum(_ready_map().values()))
    return len(v["urls"]) > SYNC_MAX_URLS or len(v["urls"]) * n_reg * len(v["encodings"]) > MAX_JOBS


def _urls_job(v, start):
    hosts = sorted({urllib.parse.urlsplit(u).hostname for u in v["urls"]})
    label = f"{len(v['urls'])} 个地址（{hosts[0]}" + (f" 等 {len(hosts)} 个域名）" if len(hosts) > 1 else "）")
    item, e = _job_create(v["urls"], v, start, "urls", label, host=hosts[0])
    if e:
        return _err(*e)
    return _resp(200, {"job": _dir_view(item), "background": True})


def _dir_create(b):
    # 只借 _validate 校验模式 / 压缩格式 / 请求头；地址由下面服务端列举得到。
    # 占位地址用白名单里的域名，免得开了 AllowedHosts 时被误拒。
    ph = ALLOWED_HOSTS[0] if ALLOWED_HOSTS else "example.invalid"
    v, e = _validate({**b, "urls": [f"https://{ph}/x"]})
    if e:
        return _err(*e)
    start, e = _parse_start(b)
    if e:
        return _err(400, e)
    # 服务端重新列一次（不信任前端传来的清单）
    res, e = _dir_list(b, full=True)
    if e:
        return _dir_err(e)
    urls = [f["url"] for f in res["files"]]
    item, e = _job_create(urls, v, start, "dir", res["host"] + res["dir"], host=res["host"], d=res["dir"])
    if e:
        return _err(*e)
    return _resp(200, {"job": _dir_view(item), "skipped_count": res["skipped_count"]})


def _dir_list_jobs():
    items = [_dir_view(it) for it in _dir_items()]
    active = sorted([x for x in items if x["status"] in ("pending", "running")], key=lambda x: x["start_at"])
    done = sorted([x for x in items if x["status"] not in ("pending", "running")], key=lambda x: -x["created"])
    return _resp(200, {"jobs": active + done[:20]})


def _dir_job(jid):
    if not jid.isalnum() or len(jid) > 32:
        return _err(400, "任务 ID 无效")
    it = _ddb.get_item(TableName=TABLE, Key=_job_key(jid), ConsistentRead=True).get("Item")
    if not it:
        return _err(404, "任务不存在或已过期")
    return _resp(200, {"job": _dir_view(it, full=True)})


def _dir_cancel(jid):
    if not jid.isalnum() or len(jid) > 32:
        return _err(400, "任务 ID 无效")
    try:
        _ddb.update_item(TableName=TABLE, Key=_job_key(jid),
                         UpdateExpression="SET #s = :c, finished = :n",
                         ConditionExpression="#s IN (:p, :r)",
                         ExpressionAttributeNames={"#s": "status"},
                         ExpressionAttributeValues={":c": {"S": "cancelled"}, ":p": {"S": "pending"},
                                                    ":r": {"S": "running"}, ":n": {"N": str(int(time.time()))}})
    except _ddb.exceptions.ConditionalCheckFailedException:
        return _err(409, "只能取消待执行或执行中的任务")
    return _resp(200, {"ok": True})


def _batch_results(jid, b):
    out, kw = [], {}
    while True:
        r = _ddb.query(TableName=TABLE, KeyConditionExpression="pk = :p AND begins_with(sk, :b)",
                       ExpressionAttributeValues={":p": {"S": "res#" + jid}, ":b": {"S": f"{b:06d}#"}},
                       ConsistentRead=True, **kw)
        out += [json.loads(x["data"]["S"]) for x in r.get("Items", [])]
        if "LastEvaluatedKey" not in r:
            return out
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


class _Lost(Exception):
    """任务被取消，或租约被别的唤醒接管：立即停止。"""


def _dir_run_one(it, context):
    """持有租约推进一个后台任务：每批先预检，再异步扇出到各区域预热函数，
    预热函数把结果写回本表，本函数汇总后推进进度。返回本次处理完的批数。"""
    jid, now = it["id"]["S"], int(time.time())
    lease, key = uuid.uuid4().hex, _job_key(jid)
    try:
        _ddb.update_item(TableName=TABLE, Key=key,
                         UpdateExpression="SET #s = :r, lease_until = :lu, lease_id = :l",
                         ConditionExpression="#s IN (:p, :r) AND lease_until < :now",
                         ExpressionAttributeNames={"#s": "status"},
                         ExpressionAttributeValues={":r": {"S": "running"}, ":p": {"S": "pending"},
                                                    ":lu": {"N": str(now + LEASE_SECONDS)},
                                                    ":l": {"S": lease}, ":now": {"N": str(now)}})
    except _ddb.exceptions.ConditionalCheckFailedException:
        return 0  # 已取消，或另一次唤醒正持有它
    st = _ddb.get_item(TableName=TABLE, Key=key, ConsistentRead=True)["Item"]
    n = lambda k: int(st.get(k, {}).get("N", "0"))
    req = json.loads(st["req"]["S"])
    total, cursor, batch = n("total"), n("cursor"), n("batch")
    c = {"files_ok": n("files_ok"), "files_failed": n("files_failed"), "bytes": n("bytes"),
         "downloads": n("downloads"), "hits": n("hits")}
    failures = json.loads(st["failures"]["S"])
    inflight = json.loads(st["inflight"]["S"]) if "inflight" in st else None
    headers = _parse_headers(req.get("headers"))
    encs = req.get("encodings") or [DEFAULT_ENCODING]
    cache, done_batches = {}, 0

    def save(extra_set="", extra_vals=None, finish=None):
        sets = ["#c = :c", "#bt = :bt", "files_ok = :o", "files_failed = :f", "#b = :b",
                "downloads = :dl", "hits = :h", "failures = :fl"]
        vals = {":c": {"N": str(cursor)}, ":bt": {"N": str(batch)}, ":o": {"N": str(c["files_ok"])},
                ":f": {"N": str(c["files_failed"])}, ":b": {"N": str(c["bytes"])},
                ":dl": {"N": str(c["downloads"])}, ":h": {"N": str(c["hits"])},
                ":fl": {"S": json.dumps(failures, ensure_ascii=False)}, ":r": {"S": "running"}, ":l": {"S": lease}}
        names = {"#c": "cursor", "#bt": "batch", "#b": "bytes", "#s": "status"}
        expr = "SET " + ", ".join(sets)
        if inflight is None:
            expr += " REMOVE inflight"
        else:
            expr = expr.replace("SET ", "SET inflight = :inf, ", 1)
            vals[":inf"] = {"S": json.dumps(inflight, ensure_ascii=False)}
        if finish:
            expr = expr.replace("SET ", "SET #s = :fs, finished = :fn, lease_until = :z, #e = :fe, ", 1)
            vals.update({":fs": {"S": finish[0]}, ":fn": {"N": str(int(time.time()))}, ":z": {"N": "0"},
                         ":fe": {"S": finish[1]}})
            names["#e"] = "error"
        try:
            _ddb.update_item(TableName=TABLE, Key=key, UpdateExpression=expr,
                             ConditionExpression="#s = :r AND lease_id = :l",
                             ExpressionAttributeNames=names, ExpressionAttributeValues=vals)
        except _ddb.exceptions.ConditionalCheckFailedException:
            raise _Lost()

    def left_ms():
        return context.get_remaining_time_in_millis() if context is not None else 10 ** 9

    try:
        while left_ms() > 60_000:
            if inflight:
                # ── 等当前批的结果 ──
                waited = time.time()
                while True:
                    res = _batch_results(jid, inflight["b"])
                    expired = time.time() > inflight["at"] + BATCH_DEADLINE
                    if len(res) >= inflight["expect"] or expired:
                        break
                    if time.time() - waited > POLL_SECONDS or left_ms() < 45_000:
                        raise _Lost()  # 还没跑完：释放租约，下一分钟再看（不是失败）
                    time.sleep(2)
                bad = dict(inflight["bad"])
                got = {}
                for x in res:
                    got.setdefault(x.get("url"), []).append(x)
                    c["bytes"] += int(x.get("bytes") or 0)
                    if x.get("ok"):
                        c["downloads"] += 1
                        if "hit from cloudfront" in (x.get("verify_x_cache") or "").lower():
                            c["hits"] += 1
                    elif x.get("url") not in bad:
                        bad[x.get("url")] = f"{x.get('region')}：{x.get('error') or '失败'}"
                for u, per in inflight["per_url"].items():
                    if u not in bad and len(got.get(u, [])) < per:
                        bad[u] = "部分区域在时限内没有返回结果（可能超时或排队过久）"
                _speed_update(res)
                c["files_failed"] += len(bad)
                c["files_ok"] += inflight["n"] - len(bad)
                for u, why in bad.items():
                    if len(failures) < DIR_MAX_FAILURES_KEPT:
                        failures.append({"url": u, "error": why[:300]})
                cursor += inflight["n"]
                batch += 1
                inflight = None
                done_batches += 1
                if cursor >= total:
                    save(finish=("done", ""))
                    return done_batches
                save()
                continue

            if cursor >= total:
                save(finish=("done", ""))
                return done_batches
            # ── 发出下一批 ──
            status = _ready_map()
            regions = ([req.get("economyRegion") or "us-east-1"] if req.get("mode") == "economy"
                       else [r for r in REGIONS if status.get(r)])
            if not regions:
                save(finish=("failed", "没有已就绪的区域，请检查 CloudFormation 部署输出"))
                return done_batches
            size = max(1, min(BATCH_MAX_FILES, BATCH_INVOKES // (len(regions) * len(encs))))
            urls = _job_files(jid, cursor, size, cache)
            if not urls:
                save(finish=("failed", "文件清单读取不完整（可能已过期），请重新创建任务"))
                return done_batches
            pre = _precheck(urls, headers)
            bad = {p["url"]: "预检未通过：" + (p.get("error") or "") for p in pre if not p["ok"]}
            good = [p["url"] for p in pre if p["ok"]]
            jobs = [(r, u, e) for u in good for r in regions for e in encs]
            per_url = {u: 0 for u in good}

            def fire(j, i):
                r, u, e = j
                h = dict(headers)
                h["Accept-Encoding"] = e
                _dispatch(r, {"url": u, "headers": h, "verify": bool(req.get("verify")),
                              "report": {"table": TABLE, "region": HOME_REGION, "pk": "res#" + jid,
                                         "sk": f"{batch:06d}#{i:05d}"}})

            with ThreadPoolExecutor(32) as t:
                futs = [(j, t.submit(fire, j, i)) for i, j in enumerate(jobs)]
            for (r, u, e), f in futs:
                try:
                    f.result()
                    per_url[u] += 1
                except Exception as x:  # noqa: BLE001 —— 发不出去如实记失败
                    bad.setdefault(u, f"{r}：调用失败 {type(x).__name__}")
            inflight = {"b": batch, "n": len(urls), "at": int(time.time()), "bad": bad,
                        "per_url": {u: k for u, k in per_url.items() if k},
                        "expect": sum(per_url.values())}
            save()
        raise _Lost()  # 时间不够：释放租约
    except _Lost:
        try:
            _ddb.update_item(TableName=TABLE, Key=key, UpdateExpression="SET lease_until = :z",
                             ConditionExpression="lease_id = :l",
                             ExpressionAttributeValues={":z": {"N": "0"}, ":l": {"S": lease}})
        except _ddb.exceptions.ConditionalCheckFailedException:
            pass
        return done_batches


def _dir_tick(context):
    now = int(time.time())
    ready = sorted([it for it in _dir_items()
                    if it["status"]["S"] in ("pending", "running")
                    and int(it["start_at"]["N"]) <= now and int(it["lease_until"]["N"]) < now],
                   key=lambda it: int(it["start_at"]["N"]))
    batches = 0
    for it in ready:
        if context is not None and context.get_remaining_time_in_millis() < 120_000:
            break
        batches += _dir_run_one(it, context)
    return {"ready": len(ready), "batches": batches}


def _save(summary, results):
    blob = json.dumps(results, ensure_ascii=False, separators=(",", ":"))
    item = {
        "pk": {"S": "run"},
        "sk": {"S": f"{summary['at']:012d}#{summary['id']}"},
        "id": {"S": summary["id"]},
        "summary": {"S": json.dumps(summary, ensure_ascii=False)},
        "ttl": {"N": str(summary["at"] + HISTORY_DAYS * 86400)},
    }
    if len(blob.encode()) < 300_000:  # DynamoDB 单条 400KB 上限
        item["results"] = {"S": blob}
    try:
        _ddb.put_item(TableName=TABLE, Item=item)
    except Exception as e:  # noqa: BLE001 —— 记录失败不影响本次结果返回
        print("save history failed:", e)


def _history():
    items = _ddb.query(TableName=TABLE, KeyConditionExpression="pk = :p",
                       ExpressionAttributeValues={":p": {"S": "run"}},
                       ScanIndexForward=False, Limit=30,
                       ProjectionExpression="summary").get("Items", [])
    return _resp(200, {"runs": [json.loads(i["summary"]["S"]) for i in items]})


def _history_one(run_id):
    if not run_id.isalnum() or len(run_id) > 32:
        return _err(400, "记录 ID 无效")
    items = _ddb.query(TableName=TABLE, KeyConditionExpression="pk = :p",
                       FilterExpression="id = :i",
                       ExpressionAttributeValues={":p": {"S": "run"}, ":i": {"S": run_id}},
                       ScanIndexForward=False).get("Items", [])
    if not items:
        return _err(404, "记录不存在或已过期")
    it = items[0]
    return _resp(200, {"summary": json.loads(it["summary"]["S"]),
                       "results": json.loads(it["results"]["S"]) if "results" in it else None})


_status_cache = {}


def _region_status():
    """各区域 worker 是否 Active，缓存 60 秒。"""
    if time.time() - _status_cache.get("at", 0) < 60:
        return _status_cache["v"]

    def probe(r):
        try:
            c = _client(r).get_function_configuration(FunctionName=FUNCTION_NAME)
            state = c.get("State")
            return r, ("ready" if state == "Active" else "pending")
        except Exception as e:  # noqa: BLE001
            m = f"{type(e).__name__} {e}"
            if "UnrecognizedClient" in m or "security token" in m:
                return r, "not_enabled"
            if "ResourceNotFound" in m:
                return r, "not_deployed"
            print("region probe failed:", r, m)
            return r, "error"
    with ThreadPoolExecutor(16) as t:
        reasons = dict(t.map(probe, REGIONS))
    _status_cache.update(v=reasons, at=time.time())
    return reasons


def _ready_map():
    return {r: s == "ready" for r, s in _region_status().items()}


def _config():
    reasons = _region_status()
    return _resp(200, {"regions": [{"region": r, "ready": reasons[r] == "ready", "reason": reasons[r]}
                                   for r in REGIONS],
                       "allowedHosts": ALLOWED_HOSTS, "maxObjectMB": MAX_OBJECT_MB,
                       "maxUrls": MAX_URLS, "syncMaxUrls": SYNC_MAX_URLS, "maxDirFiles": MAX_DIR_FILES,
                       "workerTimeout": WORKER_TIMEOUT, "home": HOME_REGION})


# ─────────────────────────── 入口 ───────────────────────────

_ctx = {}


def handler(event, context):
    _ctx["c"] = context
    # EventBridge 定时唤醒：直接调用（不经函数 URL），事件里没有 requestContext。
    # 经函数 URL 的请求一定带 requestContext，外部无法伪造成这个分支。
    if "requestContext" not in event and event.get("source") == "aws.events":
        out = _sched_tick(context)
        out["dir"] = _dir_tick(context)
        return out
    http = (event.get("requestContext") or {}).get("http") or {}
    method = http.get("method", "GET")
    path = event.get("rawPath") or "/"
    try:
        if method == "GET" and path in ("/", "/index.html"):
            return _resp(200, PANEL_HTML, "text/html; charset=utf-8")
        if not path.startswith("/api/"):
            return _err(404, "not found")
        if method == "POST" and path == "/api/login":
            b = _body(event) or {}
            pw = b.get("password")
            if not isinstance(pw, str) or not pw or len(pw) > 256:
                return _err(400, "请输入口令")
            tok = _login(pw)
            return _resp(200, {"token": tok}) if tok else _err(401, "口令错误")
        if not _authed(event):
            return _err(401, "未登录或登录已过期")
        if method == "GET" and path == "/api/config":
            return _config()
        if method == "GET" and path == "/api/history":
            return _history()
        if method == "GET" and path.startswith("/api/history/"):
            return _history_one(path.rsplit("/", 1)[-1])
        if method == "GET" and path == "/api/distributions":
            return _resp(200, {"distributions": _dists(), "maxDirFiles": MAX_DIR_FILES})  # 0 = 不限
        if method == "POST" and path in ("/api/dir/preview", "/api/dir/jobs"):
            b = _body(event)
            if b is None:
                return _err(400, "请求体不是合法 JSON")
            return _dir_preview(b) if path == "/api/dir/preview" else _dir_create(b)
        if method == "GET" and path == "/api/dir/jobs":
            return _dir_list_jobs()
        if method == "GET" and path.startswith("/api/dir/jobs/"):
            return _dir_job(path.rsplit("/", 1)[-1])
        if method == "DELETE" and path.startswith("/api/dir/jobs/"):
            return _dir_cancel(path.rsplit("/", 1)[-1])
        if method == "GET" and path == "/api/schedules":
            return _sched_list()
        if method == "POST" and path == "/api/schedules":
            b = _body(event)
            if b is None:
                return _err(400, "请求体不是合法 JSON")
            return _sched_create(b)
        if method == "DELETE" and path.startswith("/api/schedules/"):
            return _sched_cancel(path.rsplit("/", 1)[-1])
        if method == "POST" and path in ("/api/precheck", "/api/warm"):
            b = _body(event)
            if b is None:
                return _err(400, "请求体不是合法 JSON")
            if path == "/api/warm":
                return _warm(b)
            urls, e = _parse_urls(b.get("urls"))
            if e:
                return _err(400, e)
            try:
                headers = _parse_headers(b.get("headers"))
            except ValueError as x:
                return _err(400, str(x))
            return _resp(200, {"precheck": _precheck(urls, headers)})
        return _err(404, "not found")
    except Exception as e:  # noqa: BLE001
        print("panel error:", repr(e))
        return _err(500, f"服务端错误：{type(e).__name__}")
