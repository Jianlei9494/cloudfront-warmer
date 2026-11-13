#!/usr/bin/env python3
"""生成 cf-warmer.template.json（CloudFormation 一键部署模板）。

单一真值：
  - worker Lambda 代码 = cf_warmer.py 里的 LAMBDA_SOURCE（命令行版与模板版共用）
  - 面板后端 = src/panel.py，页面 = src/panel.html（构建时注入 PANEL_HTML）
  - 安装器 = src/installer.py（CloudFormation 内联代码，硬上限 4096 字符）

用法：
  python3 build_template.py           生成 / 覆盖模板
  python3 build_template.py --check   模板与源码不一致时非零退出（提交前自查）
"""

import ast
import base64
import hashlib
import json
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "cf-warmer.template.json"
INLINE_LIMIT = 4096

sys.path.insert(0, str(HERE))
from cf_warmer import DEFAULT_REGIONS, FUNCTION_NAME, LAMBDA_SOURCE  # noqa: E402

PANEL_FUNCTION = "cf-warmer-panel"

PANEL_STUB = (
    "def handler(e,c):\n"
    " return {'statusCode':503,'headers':{'Content-Type':'text/plain; charset=utf-8'},"
    "'body':'cf-warmer is installing, refresh in a minute'}\n"
)


def _strip(src: str) -> str:
    """去掉注释和文档字符串再压缩：模板必须小于 51,200 字节，install.sh 才能不经 S3 直接部署。
    行为不变（ast 往返），可读源码仍以 src/ 与 cf_warmer.py 为准。"""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body \
                and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant) \
                and isinstance(node.body[0].value.value, str):
            node.body = node.body[1:] or [ast.Pass()]
    return ast.unparse(tree) + "\n"


def _z(s: str) -> str:
    return base64.b64encode(zlib.compress(_strip(s).encode(), 9)).decode()


def build() -> str:
    installer = (HERE / "src" / "installer.py").read_text(encoding="utf-8")
    if len(installer) > INLINE_LIMIT:
        sys.exit(f"installer.py 有 {len(installer)} 字符，超过 CloudFormation 内联上限 {INLINE_LIMIT}")

    html = (HERE / "src" / "panel.html").read_text(encoding="utf-8")
    panel_src = (HERE / "src" / "panel.py").read_text(encoding="utf-8")
    marker = 'PANEL_HTML = "__PANEL_HTML__"'
    if panel_src.count(marker) != 1:
        sys.exit("panel.py 里找不到唯一的 PANEL_HTML 占位符")
    panel = panel_src.replace(marker, "PANEL_HTML = " + json.dumps(html, ensure_ascii=False))
    compile(panel, "panel.py", "exec")
    compile(LAMBDA_SOURCE, "worker.py", "exec")
    compile(installer, "installer.py", "exec")

    version = hashlib.sha256((installer + panel + LAMBDA_SOURCE).encode()).hexdigest()[:16]
    worker_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:lambda:*:${{AWS::AccountId}}:function:{FUNCTION_NAME}"}
    panel_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:{PANEL_FUNCTION}"}

    def logs_policy(fn):
        return {
            "PolicyName": "logs",
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:logs:*:${{AWS::AccountId}}:log-group:/aws/lambda/{fn}*"},
            }]},
        }

    def role(fn, extra=None):
        policies = [logs_policy(fn)]
        if extra:
            policies.append({"PolicyName": "app",
                             "PolicyDocument": {"Version": "2012-10-17", "Statement": extra}})
        return {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"}]},
            "Policies": policies,
        }}

    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "cf-warmer: CloudFront 缓存预热工具（多区域 Lambda + 网页面板），全部资源在本账号内",
        "Metadata": {"AWS::CloudFormation::Interface": {
            "ParameterGroups": [
                {"Label": {"default": "必填"}, "Parameters": ["AccessPassword"]},
                {"Label": {"default": "可选（保持默认即可）"},
                 "Parameters": ["Regions", "AllowedHosts", "MaxObjectMB", "MaxDirFiles", "WorkerMemoryMB"]},
            ],
            "ParameterLabels": {
                "AccessPassword": {"default": "面板访问口令"},
                "Regions": {"default": "预热区域"},
                "AllowedHosts": {"default": "允许预热的域名"},
                "MaxObjectMB": {"default": "单个对象上限（MB）"},
                "MaxDirFiles": {"default": "目录预热单次文件数上限"},
                "WorkerMemoryMB": {"default": "预热 Lambda 内存（MB）"},
            },
        }},
        "Parameters": {
            "AccessPassword": {"Type": "String", "NoEcho": True, "MinLength": 12, "MaxLength": 128,
                               "Description": "登录网页面板用，至少 12 位。之后可通过「更新堆栈」修改"},
            "Regions": {"Type": "CommaDelimitedList", "Default": ",".join(DEFAULT_REGIONS),
                        "Description": "CloudFront 区域边缘缓存所在区域。账号未启用的区域会被跳过，不影响其他区域"},
            "AllowedHosts": {"Type": "String", "Default": "",
                             "Description": "逗号分隔，如 cdn.example.com,img.example.com。默认留空 = 不限制，任何 https 地址都能预热。如需只允许自己的域名可在此填写"},
            "MaxObjectMB": {"Type": "Number", "Default": 0, "MinValue": 0, "MaxValue": 51200,
                            "Description": "0 = 不限（默认）。只在你想自我约束时填写"},
            "MaxDirFiles": {"Type": "Number", "Default": 0, "MinValue": 0, "MaxValue": 1000000,
                            "Description": "0 = 不限（默认）。只在你想自我约束时填写"},
            "WorkerMemoryMB": {"Type": "Number", "Default": 2048, "MinValue": 256, "MaxValue": 10240,
                               "Description": "内存越大网络越快，预热大文件时可调大"},
        },
        "Resources": {
            "Table": {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Delete", "Properties": {
                "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"},
                                         {"AttributeName": "sk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"},
                              {"AttributeName": "sk", "KeyType": "RANGE"}],
                "TimeToLiveSpecification": {"AttributeName": "ttl", "Enabled": True},
            }},
            # 预热函数被后台任务异步调用时，把结果写回面板的表
            "WorkerRole": role(FUNCTION_NAME, [
                {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": {"Fn::GetAtt": ["Table", "Arn"]}}]),
            "PanelRole": role(PANEL_FUNCTION, [
                {"Effect": "Allow", "Action": ["lambda:InvokeFunction", "lambda:GetFunctionConfiguration"],
                 "Resource": worker_arn},
                # 目录预热：只读列出分发、读分发配置、列出 S3 桶内文件
                {"Effect": "Allow", "Action": ["cloudfront:ListDistributions", "cloudfront:GetDistribution",
                                               "cloudfront:GetDistributionConfig"], "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": {"Fn::Sub": "arn:${AWS::Partition}:s3:::*"}},
                {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem"],
                 "Resource": {"Fn::GetAtt": ["Table", "Arn"]}},
            ]),
            "PanelFunction": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": PANEL_FUNCTION,
                "Description": "cf-warmer 网页面板",
                "Runtime": "python3.12", "Handler": "index.handler", "Architectures": ["arm64"],
                "MemorySize": 512, "Timeout": 900,
                "Role": {"Fn::GetAtt": ["PanelRole", "Arn"]},
                "Code": {"ZipFile": PANEL_STUB},
                "Environment": {"Variables": {
                    "TABLE": {"Ref": "Table"},
                    "REGIONS": {"Fn::Join": [",", {"Ref": "Regions"}]},
                    "ALLOWED_HOSTS": {"Ref": "AllowedHosts"},
                    "MAX_OBJECT_MB": {"Ref": "MaxObjectMB"},
                    "MAX_DIR_FILES": {"Ref": "MaxDirFiles"},
                    "WORKER_TIMEOUT": "900",
                    "PANEL_ROLE_ARN": {"Fn::GetAtt": ["PanelRole", "Arn"]},
                }},
            }},
            "PanelUrl": {"Type": "AWS::Lambda::Url", "Properties": {
                "AuthType": "NONE", "TargetFunctionArn": {"Fn::GetAtt": ["PanelFunction", "Arn"]}}},
            "PanelUrlPermission": {"Type": "AWS::Lambda::Permission", "Properties": {
                "FunctionName": {"Ref": "PanelFunction"}, "Action": "lambda:InvokeFunctionUrl",
                "Principal": "*", "FunctionUrlAuthType": "NONE"}},
            "PanelInvokePermission": {"Type": "AWS::Lambda::Permission", "Properties": {
                "FunctionName": {"Ref": "PanelFunction"}, "Action": "lambda:InvokeFunction",
                "Principal": "*", "InvokedViaFunctionUrl": True}},
            # 每分钟唤醒面板一次，执行到点的单次预定任务。
            "ScheduleTick": {"Type": "AWS::Events::Rule", "Properties": {
                "Description": "cf-warmer：每分钟检查并执行到点的预定预热",
                "ScheduleExpression": "rate(1 minute)", "State": "ENABLED",
                "Targets": [{"Id": "panel", "Arn": {"Fn::GetAtt": ["PanelFunction", "Arn"]}}]}},
            "ScheduleTickPermission": {"Type": "AWS::Lambda::Permission", "Properties": {
                "FunctionName": {"Ref": "PanelFunction"}, "Action": "lambda:InvokeFunction",
                "Principal": "events.amazonaws.com", "SourceArn": {"Fn::GetAtt": ["ScheduleTick", "Arn"]}}},
            "InstallerRole": role("cf-warmer-installer", [
                {"Effect": "Allow",
                 "Action": ["lambda:CreateFunction", "lambda:UpdateFunctionCode",
                            "lambda:UpdateFunctionConfiguration", "lambda:GetFunction",
                            "lambda:GetFunctionConfiguration", "lambda:DeleteFunction",
                            "lambda:PutFunctionEventInvokeConfig"],
                 "Resource": worker_arn},
                {"Effect": "Allow", "Action": ["lambda:UpdateFunctionCode"], "Resource": panel_arn},
                # 各函数日志组保留 30 天（日志组由 Lambda 运行时创建，不归 CloudFormation 管）
                {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:PutRetentionPolicy"],
                 "Resource": {"Fn::Sub": "arn:${AWS::Partition}:logs:*:${AWS::AccountId}:log-group:/aws/lambda/cf-warmer*"}},
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": {"Fn::GetAtt": ["WorkerRole", "Arn"]}},
                {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": {"Fn::GetAtt": ["Table", "Arn"]}},
            ]),
            "InstallerFunction": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": "cf-warmer-installer",
                "Description": "cf-warmer 安装器：在各区域部署 / 删除预热 Lambda",
                "Runtime": "python3.12", "Handler": "index.handler", "MemorySize": 256, "Timeout": 900,
                "Role": {"Fn::GetAtt": ["InstallerRole", "Arn"]},
                "Code": {"ZipFile": installer},
            }},
            "Install": {"Type": "Custom::CfWarmerInstall",
                        "DependsOn": ["PanelUrl", "PanelUrlPermission", "PanelInvokePermission"],
                        "Properties": {
                            "ServiceToken": {"Fn::GetAtt": ["InstallerFunction", "Arn"]},
                            "Version": version,
                            "Regions": {"Ref": "Regions"},
                            "WorkerRole": {"Fn::GetAtt": ["WorkerRole", "Arn"]},
                            "WorkerMemory": {"Ref": "WorkerMemoryMB"},
                            "PanelFunction": {"Ref": "PanelFunction"},
                            "Table": {"Ref": "Table"},
                            "Password": {"Ref": "AccessPassword"},
                            "WorkerZ": _z(LAMBDA_SOURCE),
                            "PanelZ": _z(panel),
                        }},
        },
        "Outputs": {
            "PanelURL": {"Description": "打开这个地址，用部署时填的口令登录",
                         "Value": {"Fn::GetAtt": ["PanelUrl", "FunctionUrl"]}},
            "DeployedRegions": {"Description": "已就绪的预热区域", "Value": {"Fn::GetAtt": ["Install", "Deployed"]}},
            "FailedRegions": {"Description": "部署失败的区域（none = 全部成功）",
                              "Value": {"Fn::GetAtt": ["Install", "Failed"]}},
        },
    }
    return json.dumps(tpl, ensure_ascii=False, separators=(",", ":")) + "\n"


INSTALL_OUT = HERE / "install.sh"
INSTALL_HEAD = r'''#!/usr/bin/env bash
# cf-warmer 一键部署脚本（由 build_template.py 生成，不要手改）。
# 在 AWS CloudShell 里运行：curl -sLO https://raw.githubusercontent.com/Jianlei9494/cloudfront-warmer/main/install.sh && bash install.sh
#   卸载：bash install.sh uninstall
# 可选环境变量：
#   CFW_REGION         面板所在区域，默认 us-east-1
#   CFW_PASSWORD       面板口令（至少 12 位），不设则自动生成
#   CFW_ALLOWED_HOSTS  只允许预热的域名，逗号分隔，默认不限制
#   CFW_MAX_OBJECT_MB  单个对象上限（MB），默认 0 = 不限
#   CFW_MAX_DIR_FILES  按目录预热一次最多文件数，默认 0 = 不限
#   CFW_WORKER_MEMORY_MB 预热函数内存（MB），默认 2048
# 每次运行都以这里的值为准（重新运行会覆盖在控制台手动改过的这些参数）。
set -euo pipefail
REGION="${CFW_REGION:-us-east-1}"
STACK=cf-warmer

command -v aws >/dev/null || { echo "找不到 aws 命令。请在 AWS 控制台右上角打开 CloudShell 运行本脚本。"; exit 1; }
ACCOUNT=$(aws sts get-caller-identity --query Account --output text) || { echo "AWS 凭证不可用"; exit 1; }

if [ "${1:-}" = "uninstall" ]; then
  echo "将删除账号 ${ACCOUNT} 中 ${REGION} 的 cf-warmer 堆栈及各区域的预热 Lambda。"
  read -r -p "确认删除？[y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "已取消"; exit 0; }
  aws cloudformation delete-stack --region "${REGION}" --stack-name "${STACK}"
  echo "删除中，约 1-2 分钟…"
  aws cloudformation wait stack-delete-complete --region "${REGION}" --stack-name "${STACK}"
  # 日志组由 Lambda 运行时创建，不归 CloudFormation 管，需单独删除。
  echo "清理各区域的运行日志…"
  for r in __CFW_REGIONS__; do
    for g in $(aws logs describe-log-groups --region "${r}" --log-group-name-prefix /aws/lambda/cf-warmer \
                 --query 'logGroups[].logGroupName' --output text 2>/dev/null || true); do
      aws logs delete-log-group --region "${r}" --log-group-name "${g}" 2>/dev/null || true
    done
  done
  echo "已删除。"
  exit 0
fi

GENERATED=0
if [ -n "${CFW_PASSWORD:-}" ]; then
  PW="$CFW_PASSWORD"
  [ ${#PW} -ge 12 ] || { echo "CFW_PASSWORD 至少 12 位"; exit 1; }
else
  PW=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20 || true)
  GENERATED=1
fi

TPL=$(mktemp)
trap 'rm -f "${TPL}"' EXIT
cat > "${TPL}" <<'CFW_TEMPLATE_EOF'
'''
INSTALL_TAIL = r'''CFW_TEMPLATE_EOF

echo "部署到账号 ${ACCOUNT}，面板区域 ${REGION}，约 3 分钟…"
aws cloudformation deploy --region "${REGION}" --stack-name "${STACK}" \
  --template-file "${TPL}" --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset \
  --parameter-overrides AccessPassword="${PW}" AllowedHosts="${CFW_ALLOWED_HOSTS:-}" \
    MaxObjectMB="${CFW_MAX_OBJECT_MB:-0}" MaxDirFiles="${CFW_MAX_DIR_FILES:-0}" \
    WorkerMemoryMB="${CFW_WORKER_MEMORY_MB:-2048}"

out() { aws cloudformation describe-stacks --region "${REGION}" --stack-name "${STACK}" \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

echo
echo "================ 部署完成 ================"
echo "面板地址：$(out PanelURL)"
if [ "${GENERATED}" = 1 ]; then
  echo "面板口令：${PW}"
  echo "（口令只显示这一次，请保存。忘记时重新运行本脚本会生成新口令）"
else
  echo "面板口令：你设置的 CFW_PASSWORD"
fi
echo "已就绪区域：$(out DeployedRegions)"
FAILED=$(out FailedRegions)
[ "${FAILED}" = "none" ] || echo "未部署区域：${FAILED}"
echo "=========================================="
'''


def build_install(template: str) -> str:
    if "\nCFW_TEMPLATE_EOF\n" in "\n" + template:
        sys.exit("模板内容里出现了 heredoc 结束符 CFW_TEMPLATE_EOF")
    regions = sorted(set(DEFAULT_REGIONS) | {"us-east-1"})
    return INSTALL_HEAD.replace("__CFW_REGIONS__", " ".join(regions)) + template + INSTALL_TAIL


def main():
    out = build()
    install = build_install(out)
    if len(out.encode()) > 51200:
        sys.exit(f"模板 {len(out.encode())} 字节，超过 CloudFormation 直传上限 51200，install.sh 将无法部署")
    if "--check" in sys.argv:
        for path, want in ((OUT, out), (INSTALL_OUT, install)):
            if not path.exists() or path.read_text(encoding="utf-8") != want:
                sys.exit(f"{path.name} 与源码不一致，请运行 python3 build_template.py")
        print("模板、安装脚本与源码一致")
        return
    OUT.write_text(out, encoding="utf-8")
    INSTALL_OUT.write_text(install, encoding="utf-8")
    INSTALL_OUT.chmod(0o755)
    print(f"已生成 {OUT.name}（{len(out.encode())} 字节）、{INSTALL_OUT.name}")


if __name__ == "__main__":
    main()
