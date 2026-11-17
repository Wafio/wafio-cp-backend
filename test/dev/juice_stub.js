// Juice-Shop-shaped stub upstream for the local WAF regression rig.
// Usage: node test/dev/juice_stub.js [port]   (default 18081)
const http = require('http');
const port = Number(process.argv[2]) || 18081;
const html = (t) => `<html><head><title>${t}</title></head><body><div id="app">` + 'A'.repeat(1000) + '</div></body></html>';
http.createServer((req, res) => {
  const u = req.url;
  if (u === '/ftp') { res.writeHead(200, {'Content-Type':'text/html; charset=utf-8','X-Recruiting':'/#/jobs'}); return res.end(html('ftp')); }
  if (u.startsWith('/ftp/')) {
    if (/\.bak|\.yml/.test(u)) { res.writeHead(403); return res.end('Only .md and .pdf files are allowed!'); }
    res.writeHead(200, {'Content-Type':'text/markdown'}); return res.end('# confidential');
  }
  if (u === '/encryptionkeys' || u === '/support/logs') { res.writeHead(200, {'Content-Type':'text/html'}); return res.end(html(u)); }
  if (u.startsWith('/rest/products/search')) {
    const q = decodeURIComponent((u.split('q=')[1]||'').split('&')[0]).replace(/\+/g,' ');
    if (q.includes("'") || q.includes('--')) { res.writeHead(500, {'Content-Type':'text/html'}); return res.end('<html><head><title>Error: SQLITE_ERROR</title></head></html>'); }
    res.writeHead(200, {'Content-Type':'application/json'}); return res.end('{"status":"success","data":[]}');
  }
  if (u === '/rest/user/login') {
    let b=''; req.on('data',c=>b+=c);
    req.on('end',()=>{ try { const j=JSON.parse(b); if (typeof j.email!=='string'||typeof j.password!=='string'){res.writeHead(401,{'Content-Type':'application/json'});return res.end('{"error":"Invalid credentials"}');} } catch(e){}
      res.writeHead(401,{'Content-Type':'application/json'}); res.end('{"error":"Invalid credentials"}'); });
    return;
  }
  if (u.startsWith('/rest/admin/')) { res.writeHead(200, {'Content-Type':'application/json'}); return res.end('{"version":"20.2.0"}'); }
  if (u === '/redirect') { res.writeHead(406); return res.end('blocked'); }
  res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'}); res.end(html('OWASP Juice Shop'));
}).listen(port, () => console.log('stub listening', port));
