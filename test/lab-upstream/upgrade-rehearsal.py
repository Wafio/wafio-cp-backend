"""Run only via ssh in the authorized isolated Linux lab after load stops."""
import hashlib,json,os,pathlib,shutil,subprocess,time,urllib.request
root=pathlib.Path('/opt/wafio-lab-20260911');out=root/'operations-closure';current=root/'build/wafio-host-agent';prior=root/'build/wafio-host-agent.pre-round2';backup=out/'build/wafio-host-agent-current'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def pid(unit):return int(subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'],text=True))
def status():return json.load(urllib.request.urlopen('http://127.0.0.1:18090/api/ebpf/trace/status',timeout=2))
def wait_ready():
 for _ in range(40):
  try:
   s=status()
   if s['running'] and s['probes']==31 and s['policies_total']==0:return s
  except Exception:pass
  time.sleep(.2)
 raise AssertionError('31-probe zero-policy lab readiness not observed')
def install(src):
 nxt=current.with_suffix('.operations-next');shutil.copy2(src,nxt);os.replace(nxt,current)
 subprocess.run(['systemctl','restart','wafio-lab-host'],check=True,timeout=10,capture_output=True)
started=time.monotonic();before=status();assert before['policies_total']==0
host_pid=pid('wafio-lab-host');waf_pid=pid('wafio-lab-waf')
assert os.readlink('/proc/'+str(host_pid)+'/exe')==str(current)
prod={n:os.readlink('/proc/'+str(n)+'/exe') for n in [2348222,2351256]}
shutil.copy2(current,backup);result={'current_sha256':sha(current),'previous_sha256':sha(prior),'original_host_pid':host_pid,'original_waf_pid':waf_pid,'before':before}
assert result['current_sha256']!=result['previous_sha256'],'no distinct rollback boundary'
try:
 install(prior);result['rollback']=wait_ready();result['rollback_pid']=pid('wafio-lab-host');result['rollback_seconds']=round(time.monotonic()-started,3)
finally:
 install(backup);result['restored']=wait_ready();result['restored_pid']=pid('wafio-lab-host');result['total_seconds']=round(time.monotonic()-started,3)
 assert sha(current)==result['current_sha256']
 assert pid('wafio-lab-waf')==waf_pid
 assert all(os.readlink('/proc/'+str(n)+'/exe')==exe for n,exe in prod.items())
 result['production_processes_unchanged']=True;result['waf_process_unchanged']=True
 (out/'upgrade-rollback.json').write_text(json.dumps(result,indent=2))
print(json.dumps({k:result[k] for k in ['rollback_seconds','total_seconds','current_sha256','previous_sha256','production_processes_unchanged','waf_process_unchanged']}))
