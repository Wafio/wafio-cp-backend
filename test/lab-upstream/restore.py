"""Native lab-only logical restore rehearsal. Never drops an existing database."""
import datetime,json,os,pathlib,socket,subprocess,time,urllib.parse,urllib.request
os.umask(0o077)
p=pathlib.Path('build/lab'); private=p/'private'
u=urllib.parse.urlparse((private/'test-db-url').read_text().strip())
assert u.hostname in ('127.0.0.1','localhost') and u.port==5433, 'requires private native lab database'
env=os.environ.copy(); env.update(PGHOST=u.hostname,PGPORT=str(u.port),PGUSER=urllib.parse.unquote(u.username),PGPASSWORD=urllib.parse.unquote(u.password),PGDATABASE='postgres')
bindir='/opt/homebrew/opt/postgresql@18/bin/'
def sql(q,db='postgres'):
 return subprocess.check_output([bindir+'psql','-XAt','-v','ON_ERROR_STOP=1','-c',q],env=env|{'PGDATABASE':db},text=True,stderr=subprocess.DEVNULL).strip()
version=sql('SELECT version FROM schema_migrations','wafio_lab'); assert version=='72'
target='wafio_restore_72_'+datetime.datetime.now().strftime('%Y%m%d%H%M%S')
backup=private/(target+'.dump'); start=time.monotonic()
subprocess.run([bindir+'pg_dump','-Fc','-f',str(backup)],env=env|{'PGDATABASE':'wafio_lab'},check=True,stderr=subprocess.DEVNULL)
result={'schema_version':version,'target_database':target,'backup_seconds':round(time.monotonic()-start,3),'backup_bytes':backup.stat().st_size,'scope':'native isolated small lab fixture; no production RPO/RTO claim'}
# Generated identifier contains only ASCII letters, digits and underscores.
sql('CREATE DATABASE '+target); sql('CREATE EXTENSION timescaledb',target);sql('SELECT timescaledb_pre_restore()',target);start=time.monotonic()
subprocess.run([bindir+'pg_restore','--exit-on-error','-d',target,str(backup)],env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
sql('SELECT timescaledb_post_restore()',target)
result['restore_seconds']=round(time.monotonic()-start,3)
assert sql('SELECT version FROM schema_migrations',target)==version
result['restored_counts']={table:int(sql('SELECT count(*) FROM '+table,target)) for table in ['users','projects','agents','host_security_events']}
result['runtime_events_with_identity']=int(sql("SELECT count(*) FROM host_security_events WHERE event_id <> ''",target))
cp_env=os.environ.copy();cp_env.update(WAFIO_DATABASE_HOST=u.hostname,WAFIO_DATABASE_PORT=str(u.port),WAFIO_DATABASE_USER=urllib.parse.unquote(u.username),WAFIO_DATABASE_PASSWORD=urllib.parse.unquote(u.password),WAFIO_DATABASE_NAME=target,WAFIO_SERVER_HTTP_ADDR='127.0.0.1:19087',WAFIO_SERVER_AGENT_GRPC_ADDR='127.0.0.1:19090',WAFIO_SERVER_FRONTEND_PATH=str(p/'dev-only-no-static'))
for port in (19087,19090):
 with socket.socket() as s:s.bind(('127.0.0.1',port))
def api(path,data=None,token=None):
 headers={'Content-Type':'application/json'}
 if token:headers['Authorization']='Bearer '+token
 req=urllib.request.Request('http://127.0.0.1:19087'+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
 with urllib.request.urlopen(req,timeout=5) as r:return json.load(r)
with (private/'restore-control-plane.log').open('wb') as log:
 proc=subprocess.Popen([str(pathlib.Path('build/wafio').resolve()),'serve'],env=cp_env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
 try:
  for _ in range(60):
   try:api('/ready');break
   except Exception:
    assert proc.poll() is None,'restore control plane exited; inspect private log'
    time.sleep(.25)
  else:raise AssertionError('restore readiness timeout')
  login=api('/api/login',{'email':'admin@wafio.test','password':(private/'admin-password').read_text().strip()})
  token=login.get('token') or login.get('access_token'); assert token,'login missing token'
  project=json.loads((private/'project.json').read_text())['id']
  restored=api('/api/projects/'+project,token=token)
  assert restored.get('id')==project,'project access did not restore'
  result.update(login_ok=True,project_access_ok=True)
 finally:
  proc.terminate()
  try:proc.wait(timeout=10)
  except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
result['source_schema_after']=sql('SELECT version FROM schema_migrations','wafio_lab');assert result['source_schema_after']==version
(p/'restore-final-evidence.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
