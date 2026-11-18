package engine

// DefaultMaintenanceMessage is the text of the maintenance page when the operator wrote no message.
const DefaultMaintenanceMessage = "We are carrying out planned maintenance. Please check back soon."

// StockMaintenanceHTML is the maintenance page the WAF agent serves when an application has no
// custom page. {{WAFIO_MESSAGE}} is the message (escaped for HTML) and {{WAFIO_END_TIME}} is the
// expected end as YYYY-MM-DDTHH:MM:SSZ, or empty. The page shows the end time in the visitor's
// time zone, and hides that line when there is none. The agent keeps a byte for byte copy of this
// page; change both together.
const StockMaintenanceHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>Down for maintenance</title>
<style>
  :root{color-scheme:dark;--bg:#0b0b17;--card:#131325;--line:rgba(245,158,11,.28);--tint:rgba(245,158,11,.1);--text:#f1f5f9;--muted:#94a3b8;--accent:#fbbf24}
  @media (prefers-color-scheme:light){:root{color-scheme:light;--bg:#f8fafc;--card:#fff;--line:rgba(180,83,9,.25);--tint:rgba(245,158,11,.1);--text:#0f172a;--muted:#475569;--accent:#92400e}}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1.5rem}
  .card{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:2.5rem 2rem;text-align:center;max-width:560px;width:100%;box-shadow:0 24px 64px rgba(0,0,0,.18)}
  .icon{width:64px;height:64px;border-radius:50%;background:var(--tint);border:1px solid var(--line);color:var(--accent);display:flex;align-items:center;justify-content:center;margin:0 auto 1.25rem}
  .icon svg{width:30px;height:30px}
  .badge{display:inline-block;background:var(--tint);border:1px solid var(--line);color:var(--accent);border-radius:6px;font-size:.72rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:.3rem .75rem;margin-bottom:1.25rem}
  h1{font-size:1.5rem;font-weight:700;letter-spacing:-.02em;margin-bottom:.75rem}
  .msg{color:var(--muted);font-size:.95rem;line-height:1.65;white-space:pre-line;overflow-wrap:anywhere}
  .eta{margin-top:1.5rem;padding:.875rem 1rem;border-radius:12px;background:var(--tint);border:1px solid var(--line);font-size:.9rem;line-height:1.5}
  .eta time{font-weight:700;color:var(--accent)}
  .foot{color:var(--muted);font-size:.75rem;margin-top:1.5rem}
  @media (max-width:480px){.card{padding:2rem 1.25rem}h1{font-size:1.3rem}}
</style>
</head>
<body>
<main class="card">
  <div class="icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg></div>
  <p class="badge">Scheduled maintenance</p>
  <h1>We'll be back soon</h1>
  <p class="msg">{{WAFIO_MESSAGE}}</p>
  <p class="eta" id="eta" hidden>Expected back by <time id="eta-time" datetime="{{WAFIO_END_TIME}}"></time></p>
</main>
<p class="foot">Thank you for your patience.</p>
<script>
(function(){var t=document.getElementById('eta-time'),v=t.getAttribute('datetime'),d=new Date(v);if(!v||isNaN(d.getTime()))return;try{t.textContent=d.toLocaleString(undefined,{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZoneName:'short'})}catch(e){t.textContent=v}document.getElementById('eta').hidden=false})();
</script>
</body>
</html>`
