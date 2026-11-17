import json,pathlib,subprocess,time,urllib.request
root=pathlib.Path('/opt/wafio-lab-20260911/operations-closure');drop=pathlib.Path('/run/systemd/system/wafio-lab-host.service.d/operations-closure.conf')
assert not drop.exists(),'refuse to overwrite an existing override'
def status():return json.load(urllib.request.urlopen('http://127.0.0.1:18090/api/ebpf/trace/status',timeout=3))
assert status()['policies_total']==0
body='''[Service]
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_PERFMON CAP_KILL CAP_SYS_RESOURCE CAP_SYS_PTRACE
AmbientCapabilities=
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_PERFMON CAP_KILL CAP_SYS_RESOURCE CAP_SYS_PTRACE
LimitMEMLOCK=infinity
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ReadWritePaths=/opt/wafio-lab-20260911 /sys/fs/bpf
'''
drop.parent.mkdir(parents=True,exist_ok=True);drop.write_text(body)
(root/'host-hardening.conf').write_text(body)
try:
 subprocess.run(['systemctl','daemon-reload'],check=True,capture_output=True,timeout=10)
 subprocess.run(['systemctl','restart','wafio-lab-host'],check=True,capture_output=True,timeout=15)
 for _ in range(40):
  try:
   s=status()
   if s['running'] and s['probes']==31 and s['policies_total']==0:break
  except Exception:pass
  time.sleep(.25)
 else:raise AssertionError('hardened host did not reach readiness')
 props=subprocess.check_output(['systemctl','show','wafio-lab-host','-p','ProtectSystem','-p','CapabilityBoundingSet','-p','NoNewPrivileges','-p','ReadWritePaths','-p','MainPID'],text=True)
 result={'status':s,'properties':props,'rollback':'remove only operations-closure.conf, daemon-reload, restart only wafio-lab-host'}
 (root/'host-hardening.json').write_text(json.dumps(result,indent=2));print(props)
except Exception:
 drop.unlink();subprocess.run(['systemctl','daemon-reload'],check=True,capture_output=True);subprocess.run(['systemctl','restart','wafio-lab-host'],check=True,capture_output=True)
 raise
