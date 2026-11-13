import json,io,os,time,zipfile,hashlib,zlib,base64,urllib.request,boto3
from concurrent.futures import ThreadPoolExecutor as T
N="cf-warmer"
def send(e,c,s,r="",d=None):
 b=json.dumps({"Status":s,"Reason":(r+" | log: "+c.log_stream_name)[:1000],"PhysicalResourceId":"cf-warmer-install","StackId":e["StackId"],"RequestId":e["RequestId"],"LogicalResourceId":e["LogicalResourceId"],"Data":d or {}}).encode()
 urllib.request.urlopen(urllib.request.Request(e["ResponseURL"],b,{"Content-Type":""},method="PUT"),timeout=30)
def u(s):return zlib.decompress(base64.b64decode(s)).decode()
def z(s):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as f:f.writestr("index.py",s)
 return b.getvalue()
def lg(r,n):
 try:
  l=boto3.client("logs",region_name=r)
  try:l.create_log_group(logGroupName=n)
  except l.exceptions.ResourceAlreadyExistsException:pass
  l.put_retention_policy(logGroupName=n,retentionInDays=30)
 except Exception as x:print("retention",r,n,x)
def put(r,p):
 lg(r,"/aws/lambda/"+N)
 c=boto3.client("lambda",region_name=r);k=z(u(p["WorkerZ"]))
 g=dict(Runtime="python3.12",Handler="index.handler",Role=p["WorkerRole"],MemorySize=int(p["WorkerMemory"]),Timeout=900,Description="CloudFront cache warmer (cf-warmer)")
 try:c.get_function(FunctionName=N)
 except c.exceptions.ResourceNotFoundException:
  for i in range(30):
   try:
    c.create_function(FunctionName=N,Code={"ZipFile":k},Architectures=["arm64"],**g);break
   except c.exceptions.InvalidParameterValueException as x:
    if "assume" not in str(x).lower() or i==29:raise
    time.sleep(3)
 else:
  c.update_function_code(FunctionName=N,ZipFile=k,Architectures=["arm64"])
  c.get_waiter("function_updated_v2").wait(FunctionName=N)
  c.update_function_configuration(FunctionName=N,**g)
 c.put_function_event_invoke_config(FunctionName=N,MaximumRetryAttempts=0,MaximumEventAgeInSeconds=1200)
def rm(r,p=None):
 c=boto3.client("lambda",region_name=r)
 try:c.delete_function(FunctionName=N)
 except c.exceptions.ResourceNotFoundException:pass
def each(f,rs,p=None):
 bad={}
 with T(8) as t:fs={r:t.submit(f,r,p) for r in rs}
 for r,x in fs.items():
  try:x.result()
  except Exception as y:bad[r]="region not enabled in this account" if "UnrecognizedClient" in str(y) else type(y).__name__+": "+str(y)[:120]
 return bad
def handler(e,c):
 try:
  p=e["ResourceProperties"];rs=[r.strip() for r in p.get("Regions",[]) if r.strip()]
  if e["RequestType"]=="Delete":
   each(rm,rs);return send(e,c,"SUCCESS","removed")
  if e["RequestType"]=="Update":
   o=e.get("OldResourceProperties",{}).get("Regions",[]);each(rm,[r for r in o if r not in rs])
  boto3.client("lambda").update_function_code(FunctionName=p["PanelFunction"],ZipFile=z(u(p["PanelZ"])))
  s=os.urandom(16).hex();h=hashlib.pbkdf2_hmac("sha256",p["Password"].encode(),bytes.fromhex(s),200000).hex()
  boto3.client("dynamodb").put_item(TableName=p["Table"],Item={"pk":{"S":"config"},"sk":{"S":"auth"},"salt":{"S":s},"hash":{"S":h}})
  for n in (p["PanelFunction"],c.function_name):lg(os.environ["AWS_REGION"],"/aws/lambda/"+n)
  bad=each(put,rs,p);ok=[r for r in rs if r not in bad]
  if not ok:return send(e,c,"FAILED","all regions failed: "+json.dumps(bad))
  send(e,c,"SUCCESS","ok",{"Deployed":", ".join(ok),"Failed":"; ".join(r+" ("+m+")" for r,m in bad.items()) or "none"})
 except Exception as x:
  send(e,c,"FAILED" if e.get("RequestType")!="Delete" else "SUCCESS",type(x).__name__+": "+str(x)[:500])
