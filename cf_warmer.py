#!/usr/bin/env python3
"""cf-warmer — 用你自己 AWS 账号里的 Lambda 预热 CloudFront 缓存。

原理：在多个 AWS 区域各部署一个小 Lambda。每个 Lambda 对目标 URL 发一次完整 GET，
请求会落到离该区域最近的 CloudFront 边缘节点，对象随之被缓存到该节点及其区域边缘缓存（REC）。
默认覆盖 CloudFront 的 13 个区域边缘缓存所在区域。

全部资源都在你自己的账号里，不依赖任何第三方服务。

子命令：
  deploy   在各区域创建 / 更新 Lambda（以及一个只有写日志权限的 IAM 角色）
  run      预热一个或多个 URL
  status   查看各区域 Lambda 是否就绪
  destroy  删除各区域 Lambda 和 IAM 角色

依赖：Python 3.10+、boto3（pip install boto3），以及可用的 AWS 凭证（环境变量 / ~/.aws / --profile）。
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

FUNCTION_NAME = "cf-warmer"
ROLE_NAME = "cf-warmer-lambda-role"
INLINE_POLICY_NAME = "cf-warmer-logs"
# 只允许写自己函数的 CloudWatch 日志（等价于 AWSLambdaBasicExecutionRole，范围更小）。
LOGS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": f"arn:aws:logs:*:*:log-group:/aws/lambda/{FUNCTION_NAME}*",
    }],
}

# CloudFront 区域边缘缓存（Regional Edge Cache）所在的 13 个 AWS 区域。
# me-central-1 是需要手动启用的区域；账号未启用时 deploy 会跳过并提示。
DEFAULT_REGIONS = [
    "us-east-1", "us-east-2", "us-west-2",
    "eu-central-1", "eu-west-1", "eu-west-2",
    "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-south-1",
    "sa-east-1", "me-central-1",
]

# 浏览器常见的 Accept-Encoding。开启压缩的分发会按压缩格式分别缓存，
# 需要预热多个变体时用 --encodings 指定。
DEFAULT_ENCODING = "gzip, deflate, br"

# ─────────────────────────── Lambda 代码（部署到各区域） ───────────────────────────

LAMBDA_SOURCE = r'''
import json, os, ssl, time, urllib.error, urllib.request

CHUNK = 256 * 1024
SAFETY_MS = 5000  # 留给返回结果的时间


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # 不跟随重定向：跳到别的地址会把别的对象热了，而目标对象并没热。
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def _pick(h):
    return {
        "x_cache": h.get("X-Cache"),
        "pop": h.get("X-Amz-Cf-Pop"),
        "age": h.get("Age"),
        "content_length": h.get("Content-Length"),
        "content_encoding": h.get("Content-Encoding"),
        "via": h.get("Via"),
    }


def _is_cloudfront(h):
    # CloudFront 的每个响应都带 X-Amz-Cf-Pop，Via 里也有 "(CloudFront)"。
    return bool(h.get("X-Amz-Cf-Pop")) or "cloudfront" in (h.get("Via") or "").lower()


NOT_CF = "响应不是来自 CloudFront（该地址没有经过 CloudFront 分发），预热不会生效"


def _open(url, method, headers, timeout):
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        return _OPENER.open(req, timeout=timeout), None
    except urllib.error.HTTPError as e:
        return None, e


def _run(event, context):
    url = event["url"]
    headers = dict(event.get("headers") or {})
    headers.setdefault("User-Agent", "cf-warmer/1.0")
    out = {"url": url, "region": os.environ.get("AWS_REGION"), "ok": False,
           "status": None, "bytes": 0, "complete": False, "error": None}
    if not url.lower().startswith("https://"):
        out["error"] = "只支持 https:// URL"
        return out

    t0 = time.time()
    resp, herr = _open(url, "GET", headers, 30)
    if herr is not None:
        out["status"] = herr.code
        out.update(_pick(herr.headers))
        out["error"] = "HTTP %d，对象未被缓存" % herr.code
        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        return out

    with resp:
        out["status"] = resp.status
        out.update(_pick(resp.headers))
        out["cloudfront"] = _is_cloudfront(resp.headers)
        if not out["cloudfront"]:
            # 不是 CloudFront：不下载正文，避免白白给源站 / 别家 CDN 增加流量。
            out["error"] = NOT_CF
            out["elapsed_ms"] = int((time.time() - t0) * 1000)
            return out
        n = 0
        aborted = False
        while True:
            if context.get_remaining_time_in_millis() < SAFETY_MS:
                aborted = True
                break
            buf = resp.read(CHUNK)
            if not buf:
                break
            n += len(buf)
        out["bytes"] = n

    cl = out.get("content_length")
    if aborted:
        out["error"] = "Lambda 超时前未下载完（已下载 %d 字节），请调大 --timeout 或 --memory 后重新 deploy" % n
    elif cl is not None and cl.isdigit() and int(cl) != n:
        out["error"] = "下载不完整：Content-Length=%s，实际 %d 字节" % (cl, n)
    else:
        out["complete"] = True
    out["ok"] = out["complete"] and 200 <= out["status"] < 300
    out["elapsed_ms"] = int((time.time() - t0) * 1000)

    # 可选：再发一次 HEAD，看边缘是否已命中缓存。
    # 同一节点内有多台缓存服务器，紧跟着的 HEAD 偶尔落到还没拿到对象的那台，
    # 所以未命中时间隔重试，最多 3 次。
    if out["ok"] and event.get("verify"):
        for attempt in range(3):
            if attempt:
                time.sleep(2)
            vresp, verr = _open(url, "HEAD", headers, 15)
            h = (vresp.headers if vresp is not None else verr.headers)
            out["verify_x_cache"] = h.get("X-Cache")
            out["verify_pop"] = h.get("X-Amz-Cf-Pop")
            out["verify_attempts"] = attempt + 1
            if vresp is not None:
                vresp.close()
            if "hit from cloudfront" in (out["verify_x_cache"] or "").lower():
                break
    return out


def handler(event, context):
    try:
        out = _run(event, context)
    except Exception as e:  # noqa: BLE001 —— 任何异常都要如实回报，不能让结果凭空消失
        out = {"url": event.get("url"), "region": os.environ.get("AWS_REGION"), "ok": False,
               "bytes": 0, "error": "预热函数出错：%s" % type(e).__name__}
    # 面板的后台任务用异步调用：结果写回面板的表，面板再汇总。
    rep = event.get("report")
    if rep:
        try:
            import boto3
            boto3.client("dynamodb", region_name=rep["region"]).put_item(TableName=rep["table"], Item={
                "pk": {"S": rep["pk"]}, "sk": {"S": rep["sk"]},
                "data": {"S": json.dumps(out, ensure_ascii=False)},
                "ttl": {"N": str(int(time.time()) + 7 * 86400)}})
        except Exception as e:  # noqa: BLE001
            print("report failed:", repr(e))
    return out
'''


def _lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("lambda_function.py", LAMBDA_SOURCE)
    return buf.getvalue()


# ─────────────────────────── boto3 ───────────────────────────

def _session(profile):
    try:
        import boto3
    except ImportError:
        sys.exit("缺少 boto3：请先运行 pip install boto3")
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def _lambda_client(sess, region, read_timeout=60):
    from botocore.config import Config
    return sess.client("lambda", region_name=region,
                       config=Config(read_timeout=read_timeout, connect_timeout=10,
                                     retries={"max_attempts": 2}))


def _ensure_role(sess) -> str:
    iam = sess.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    try:
        arn = iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"]
        print(f"IAM 角色已存在：{ROLE_NAME}")
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(RoleName=ROLE_NAME, AssumeRolePolicyDocument=json.dumps(trust),
                              Description="cf-warmer Lambda 执行角色（仅写 CloudWatch 日志）")["Role"]["Arn"]
        print(f"已创建 IAM 角色：{ROLE_NAME}")
    iam.put_role_policy(RoleName=ROLE_NAME, PolicyName=INLINE_POLICY_NAME,
                        PolicyDocument=json.dumps(LOGS_POLICY))
    return arn


def _set_log_retention(sess, region, days=30):
    """预先建好日志组并设保留期（否则 Lambda 运行时会建一个永不过期的）。失败不影响部署。"""
    logs = sess.client("logs", region_name=region)
    name = f"/aws/lambda/{FUNCTION_NAME}"
    try:
        try:
            logs.create_log_group(logGroupName=name)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass
        logs.put_retention_policy(logGroupName=name, retentionInDays=days)
    except Exception as e:  # noqa: BLE001
        print(f"  {region:<16} 日志保留期设置失败（不影响使用）：{type(e).__name__}")


def _deploy_region(sess, region, role_arn, memory, timeout, arch):
    _set_log_retention(sess, region)
    client = _lambda_client(sess, region)
    code = _lambda_zip()
    cfg = dict(Runtime="python3.12", Handler="lambda_function.handler", Role=role_arn,
               MemorySize=memory, Timeout=timeout,
               Description="CloudFront 缓存预热（cf-warmer）")
    try:
        client.get_function(FunctionName=FUNCTION_NAME)
        exists = True
    except client.exceptions.ResourceNotFoundException:
        exists = False

    if exists:
        client.update_function_code(FunctionName=FUNCTION_NAME, ZipFile=code, Architectures=[arch])
        client.get_waiter("function_updated_v2").wait(FunctionName=FUNCTION_NAME)
        client.update_function_configuration(FunctionName=FUNCTION_NAME, **cfg)
        client.get_waiter("function_updated_v2").wait(FunctionName=FUNCTION_NAME)
        return "已更新"

    # 新建的 IAM 角色需要几秒才能被 Lambda 识别，这里重试。
    for attempt in range(12):
        try:
            client.create_function(FunctionName=FUNCTION_NAME, Code={"ZipFile": code},
                                   Architectures=[arch], **cfg)
            break
        except client.exceptions.InvalidParameterValueException as e:
            if "assume" in str(e).lower() and attempt < 11:
                time.sleep(5)
                continue
            raise
    client.get_waiter("function_active_v2").wait(FunctionName=FUNCTION_NAME)
    return "已创建"


def cmd_deploy(args):
    sess = _session(args.profile)
    role_arn = _ensure_role(sess)
    failed = 0
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(_deploy_region, sess, r, role_arn, args.memory, args.timeout, args.arch): r
                for r in args.regions}
        for f in as_completed(futs):
            r = futs[f]
            try:
                print(f"  {r:<16} {f.result()}")
            except Exception as e:  # noqa: BLE001 —— 逐区域报告，不因一个区失败中断其余
                failed += 1
                hint = "（该区域可能未在账号中启用）" if "UnrecognizedClient" in str(e) or "security token" in str(e) else ""
                print(f"  {r:<16} 失败{hint}：{e}")
    print(f"\n完成：{len(args.regions) - failed} 个区域就绪，{failed} 个失败。")
    return 1 if failed else 0


def cmd_status(args):
    sess = _session(args.profile)
    ready = 0
    for r in args.regions:
        try:
            c = _lambda_client(sess, r).get_function_configuration(FunctionName=FUNCTION_NAME)
            print(f"  {r:<16} {c.get('State')}  内存 {c['MemorySize']} MB  超时 {c['Timeout']} s")
            ready += c.get("State") == "Active"
        except Exception as e:  # noqa: BLE001
            print(f"  {r:<16} 不可用：{type(e).__name__}")
    print(f"\n{ready}/{len(args.regions)} 个区域就绪。")
    return 0 if ready == len(args.regions) else 1


def cmd_destroy(args):
    sess = _session(args.profile)
    for r in args.regions:
        try:
            _lambda_client(sess, r).delete_function(FunctionName=FUNCTION_NAME)
            print(f"  {r:<16} 已删除")
        except Exception as e:  # noqa: BLE001
            print(f"  {r:<16} 跳过：{type(e).__name__}")
    if args.keep_role:
        return 0
    iam = sess.client("iam")
    try:
        try:
            iam.delete_role_policy(RoleName=ROLE_NAME, PolicyName=INLINE_POLICY_NAME)
        except iam.exceptions.NoSuchEntityException:
            pass
        iam.delete_role(RoleName=ROLE_NAME)
        print(f"已删除 IAM 角色：{ROLE_NAME}")
    except iam.exceptions.NoSuchEntityException:
        print("IAM 角色不存在，跳过")
    return 0


# ─────────────────────────── run ───────────────────────────

def _parse_headers(items):
    out = {}
    for h in items or []:
        k, sep, v = h.partition(":")
        if not sep or not k.strip():
            sys.exit(f"--header 格式应为 '名称: 值'，收到：{h}")
        out[k.strip()] = v.strip()
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _local_head(url, headers):
    """本机发 HEAD 估算大小。返回 (状态码或 None, Content-Length 或 None, 错误文本)。"""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "cf-warmer/1.0", **headers})
    try:
        # 与 Lambda 一致：不跟随重定向，3xx 视为不可预热。
        with _NO_REDIRECT_OPENER.open(req, timeout=15) as r:
            if not (r.headers.get("X-Amz-Cf-Pop") or "cloudfront" in (r.headers.get("Via") or "").lower()):
                return r.status, None, "NOT_CF"
            cl = r.headers.get("Content-Length")
            return r.status, int(cl) if cl and cl.isdigit() else None, ""
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, None, str(e)


def _fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return str(n)


def _validate_url(u):
    p = urllib.parse.urlsplit(u)
    if p.scheme.lower() != "https" or not p.hostname:
        sys.exit(f"只支持完整的 https:// URL：{u}")
    if "*" in p.path:
        sys.exit(f"不支持通配符（预热必须是具体对象）：{u}")


def cmd_run(args):
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            urls += [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    if not urls:
        sys.exit("没有要预热的 URL")
    for u in urls:
        _validate_url(u)

    regions = [args.economy_region] if args.mode == "economy" else args.regions
    encodings = [e.strip() for e in args.encodings.split("|")] if args.encodings else [DEFAULT_ENCODING]
    base_headers = _parse_headers(args.header)

    # 1) 预检：本机 HEAD，估算流量，拦住超大 / 错误对象。
    print("预检：")
    total = 0
    unknown = 0
    jobs_urls = []
    for u in urls:
        status, size, err = _local_head(u, base_headers)
        if err == "NOT_CF":
            print(f"  ✗ {u}  不是 CloudFront 分发的地址（响应头没有 CloudFront 标识），预热不会生效，跳过")
            continue
        if status is None or status >= 300:
            why = f"返回 {err}，重定向或错误响应不会被预热" if status else f"无法访问：{err}"
            print(f"  ✗ {u}  {why}，跳过")
            continue
        if size is None:
            unknown += 1
            print(f"  ? {u}  大小未知（无 Content-Length）")
        else:
            if args.max_mb and size > args.max_mb * 1024 * 1024:
                print(f"  ✗ {u}  {_fmt_bytes(size)} 超过 --max-mb {args.max_mb}，跳过")
                continue
            total += size
            print(f"  ✓ {u}  {_fmt_bytes(size)}")
        jobs_urls.append(u)
    if not jobs_urls:
        print("没有可预热的 URL。")
        return 1

    n_req = len(jobs_urls) * len(regions) * len(encodings)
    est = total * len(regions) * len(encodings)
    print(f"\n将从 {len(regions)} 个区域 × {len(encodings)} 种编码预热 {len(jobs_urls)} 个 URL，"
          f"共 {n_req} 次完整下载，预计 CloudFront 出向流量最多约 {_fmt_bytes(est)}（按未压缩大小估算，开启压缩时实际更少）"
          + (f"（另有 {unknown} 个 URL 大小未知未计入）" if unknown else "")
          + "。\n流量按你账号的 CloudFront 费率计费；源站未开 Origin Shield 时回源也会放大。")
    if not args.yes:
        if input("确认执行？[y/N] ").strip().lower() not in ("y", "yes"):
            print("已取消。")
            return 1

    # 2) 扇出：每个 (区域, URL, 编码) 一次 Lambda 调用。
    sess = _session(args.profile)
    clients = {r: _lambda_client(sess, r, read_timeout=args.invoke_timeout) for r in regions}

    def invoke(region, url, enc):
        headers = dict(base_headers)
        headers["Accept-Encoding"] = enc
        payload = {"url": url, "headers": headers, "verify": args.verify}
        try:
            resp = clients[region].invoke(FunctionName=FUNCTION_NAME, Payload=json.dumps(payload).encode())
            body = json.loads(resp["Payload"].read() or b"{}")
            if resp.get("FunctionError"):
                return {"url": url, "region": region, "ok": False,
                        "error": f"Lambda 执行出错：{body.get('errorMessage', body)}"}
            body["encoding"] = enc
            return body
        except Exception as e:  # noqa: BLE001 —— 单点失败要如实报告，不能拖垮整轮
            m = str(e)
            why = ("该区域未在账号中启用" if "UnrecognizedClient" in m
                   else "该区域未部署，请先运行 deploy" if "ResourceNotFound" in m
                   else f"{type(e).__name__}: {m}")
            return {"url": url, "region": region, "ok": False, "encoding": enc, "error": f"调用失败：{why}"}

    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(invoke, r, u, e) for u in jobs_urls for r in regions for e in encodings]
        for f in as_completed(futs):
            results.append(f.result())

    # 3) 报告。
    results.sort(key=lambda x: (x.get("url", ""), x.get("encoding", ""), x.get("region", "")))
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        cur = None
        for x in results:
            key = (x.get("url"), x.get("encoding"))
            if key != cur:
                cur = key
                print(f"\n{x.get('url')}  [Accept-Encoding: {x.get('encoding')}]")
            mark = "✓" if x.get("ok") else "✗"
            line = (f"  {mark} {x.get('region', ''):<16} 节点 {x.get('pop') or '-':<10} "
                    f"状态 {x.get('status') or '-':<4} {_fmt_bytes(x.get('bytes', 0)):>10}  "
                    f"首次 {x.get('x_cache') or '-'}")
            if x.get("verify_x_cache"):
                line += f"  → 复查 {x['verify_x_cache']}"
            if x.get("error"):
                line += f"  {x['error']}"
            print(line)

    ok = sum(1 for x in results if x.get("ok"))
    moved = sum(x.get("bytes", 0) for x in results)
    print(f"\n成功 {ok}/{len(results)}，实际下载 {_fmt_bytes(moved)}。")
    return 0 if ok == len(results) else 2


# ─────────────────────────── CLI ───────────────────────────

def main(argv=None):
    p = argparse.ArgumentParser(description="用你自己 AWS 账号里的 Lambda 预热 CloudFront 缓存")
    p.add_argument("--profile", help="AWS CLI profile 名（默认用默认凭证链）")
    p.add_argument("--regions", type=lambda s: [r.strip() for r in s.split(",") if r.strip()],
                   default=DEFAULT_REGIONS, help="逗号分隔的区域列表（默认 13 个区域边缘缓存区域）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("deploy", help="创建 / 更新各区域 Lambda")
    d.add_argument("--memory", type=int, default=2048, help="Lambda 内存 MB（越大网络越快，默认 2048）")
    d.add_argument("--timeout", type=int, default=900, help="Lambda 超时秒数，最大 900（默认 900）")
    d.add_argument("--arch", choices=["arm64", "x86_64"], default="arm64")
    d.set_defaults(func=cmd_deploy)

    s = sub.add_parser("status", help="查看各区域 Lambda 状态")
    s.set_defaults(func=cmd_status)

    x = sub.add_parser("destroy", help="删除各区域 Lambda 与 IAM 角色")
    x.add_argument("--keep-role", action="store_true", help="保留 IAM 角色")
    x.set_defaults(func=cmd_destroy)

    r = sub.add_parser("run", help="预热 URL")
    r.add_argument("urls", nargs="*", help="要预热的完整 https URL")
    r.add_argument("-f", "--file", help="URL 列表文件，一行一个，# 开头为注释")
    r.add_argument("--mode", choices=["full", "economy"], default="full",
                   help="full=每个区域都预热；economy=只从一个区域预热（分发开了 Origin Shield 时可保护源站）")
    r.add_argument("--economy-region", default="us-east-1", help="economy 模式使用的区域（默认 us-east-1）")
    r.add_argument("--encodings", help="要预热的 Accept-Encoding 变体，用 | 分隔，如 'br|gzip|identity'")
    r.add_argument("-H", "--header", action="append", help="额外请求头，如 'Cookie: a=b'，可重复")
    r.add_argument("--verify", action="store_true", help="预热后再发一次 HEAD，确认边缘已命中")
    r.add_argument("--max-mb", type=int, default=0, help="单个对象大小上限 MB，0 = 不限（默认）")
    r.add_argument("--concurrency", type=int, default=16, help="同时进行的 Lambda 调用数（默认 16）")
    r.add_argument("--invoke-timeout", type=int, default=930, help="等待单次调用返回的秒数（默认 930）")
    r.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    r.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    r.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    if getattr(args, "timeout", 600) > 900:
        sys.exit("--timeout 不能超过 900（Lambda 上限 15 分钟）")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
