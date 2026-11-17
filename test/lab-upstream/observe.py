import json,os,pathlib,subprocess,time,datetime
host=os.environ['WAFIO_LAB_HOST']  # ssh name of the lab server
p=pathlib.Path('build/lab'); samples=[];start=time.monotonic()
for i in range(21):
 script="""import json,urllib.request,subprocess
s=json.load(urllib.request.urlopen('http://127.0.0.1:18090/api/ebpf/trace/status',timeout=4))
r=subprocess.check_output(['systemctl','show','wafio-lab-host','wafio-lab-waf','-p','MainPID','-p','MemoryCurrent','-p','CPUUsageNSec','-p','ActiveState'],text=True)
prod=subprocess.check_output(['ps','-p','2348222,2351256','-o','pid=,comm='],text=True)
print(json.dumps({'trace':s,'resources':r,'production_processes':prod}))
"""
 try:
  r=subprocess.run(['ssh',host,'python3','-'],input=script,text=True,capture_output=True,timeout=10,check=True)
  samples.append({'elapsed_seconds':round(time.monotonic()-start,2),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'remote':json.loads(r.stdout)})
 except Exception as ex:samples.append({'elapsed_seconds':round(time.monotonic()-start,2),'error':type(ex).__name__})
 (p/'operations-observation.json').write_text(json.dumps(samples,indent=2))
 if i<20:time.sleep(max(0,start+(i+1)*15-time.monotonic()))
print('Observation complete:',len(samples),'samples')
