-- Load for the rollup reader timing test (TestRollupAppReadersPerf). Run it once, on a TimescaleDB
-- database that has every migration and no decisions:
--
--   psql -v ON_ERROR_STOP=1 -d wafio_perf -f rollup_perf.sql
--
-- It adds one project with one agent and two apps (ids ending b1 and b2). App b1 gets 1.1 M decisions a day for 30 days
-- (33 M), in the shape measured on a customer install: 63 k to 79 k client addresses and 250 k to
-- 520 k URIs a day, 74 % of the URIs with a query string, 3.3 k user agents, 97.2 % allow, 2.5 %
-- block and 0.3 % log. App b2 gets a tenth of that. Each day is its own transaction, and a chunk
-- older than a day is compressed as soon as it is loaded, so the table never holds more than two
-- days uncompressed. Recorded times run from the start of the UTC day 30 days ago to now.
--
-- Adding -v per_day=20000 -v days=2 loads a small set, to try a change to this file.
\if :{?per_day} \else \set per_day 1100000 \endif
\if :{?days} \else \set days 30 \endif

INSERT INTO users (id, email, password_hash, name)
VALUES ('00000000-0000-4000-8000-0000000000a1', 'perf@wafio.test', 'x', 'perf') ON CONFLICT DO NOTHING;
INSERT INTO projects (id, user_id, name, code)
VALUES ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000a1', 'perf', 'perf') ON CONFLICT DO NOTHING;
INSERT INTO agents (id, user_id, project_id, name, kind)
VALUES ('00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-0000000000a1',
        '00000000-0000-4000-8000-0000000000a2', 'perf-agent', 'waf') ON CONFLICT DO NOTHING;

-- Decisions of one app recorded in [from_ts, to_ts). The pools scale with n, so a small set keeps the
-- same shape. A client, a URI and a user agent are drawn with a skew towards low numbers; the path of
-- a URI follows from its number, so the same query string always has the same path. The 20 k clients
-- with the lowest numbers come back every day, the others are new each day, so 30 days hold about 1.5 M.
CREATE FUNCTION pg_temp.perf_rows(from_ts timestamptz, to_ts timestamptz, n int, app uuid) RETURNS void
LANGUAGE sql AS $f$
INSERT INTO waf_decisions (agent_id, app_id, host, method, uri, remote_addr, country_code, user_agent, content_type,
                           action, score, categories, analyze_method, body_size, latency_us, match_source, status,
                           event_time, recorded_at)
SELECT '00000000-0000-4000-8000-0000000000a3', app, 'www.example.test',
       (ARRAY['GET', 'GET', 'GET', 'POST', 'HEAD'])[1 + floor(r.r1 * 5)::int],
       '/' || (ARRAY['api', 'static', 'blog', 'shop', 'wp-content'])[1 + u % 5] || '/p' || u % 2000 ||
           CASE WHEN r.r4 < 0.74 THEN '?q=' || u ELSE '' END,
       (11 + a / 65536) || '.' || (a / 256 % 256) || '.' || (a % 256) || '.1',
       (ARRAY['ID', 'US', 'SG', 'DE', 'CN', 'RU', 'BR', 'IN'])[1 + floor(r.r7 ^ 2 * 8)::int],
       'Mozilla/5.0 (compatible; perf-' || floor(3300 * r.r8 ^ 2)::int || ') AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
       'text/html',
       act, CASE act WHEN 'allow' THEN 0 ELSE 5 + floor(r.r9 * 10)::int END,
       CASE act WHEN 'allow' THEN '{}'::text[] ELSE ARRAY[(ARRAY['SQLi', 'XSS', 'RCE', 'PathTraversal', 'Scanner'])[1 + floor(r.r10 * 5)::int]] END,
       CASE WHEN act = 'allow' AND r.r11 < 0.4 THEN NULL WHEN r.r11 < 0.8 THEN 'semantic' ELSE 'rule_based' END,
       floor(r.r12 * 2000)::int, (200 + 5000 * r.r13 ^ 3)::int, (ARRAY[NULL, NULL, 'rule', 'ws:message'])[1 + floor(r.r14 * 4)::int],
       CASE act WHEN 'block' THEN 403 ELSE 200 END,
       at - (r.r15 * 2) * interval '1 second', at
FROM (
    SELECT random() AS r1, random() AS r4, random() AS r5, random() AS r6, random() AS r7, random() AS r8, random() AS r9,
           random() AS r10, random() AS r11, random() AS r12, random() AS r13, random() AS r14, random() AS r15,
           random() AS r16, random() AS r17
    FROM generate_series(1, n)
) r
CROSS JOIN LATERAL (SELECT floor(71000.0 * n / 1100000 * r.r6 ^ 1.5)::int AS c) c0
CROSS JOIN LATERAL (SELECT c0.c + CASE WHEN c0.c >= 20000 THEN 45000 * (floor(extract(epoch FROM from_ts) / 86400)::int % 40) ELSE 0 END AS a,
                           floor(600000.0 * n / 1100000 * r.r5 ^ 2)::int AS u,
                           CASE WHEN r.r16 < 0.972 THEN 'allow' WHEN r.r16 < 0.997 THEN 'block' ELSE 'log' END AS act,
                           from_ts + r.r17 * (to_ts - from_ts) AS at) x
$f$;

-- Per day: the decisions of both apps, then the compression of every chunk older than a day. \gexec runs
-- each statement as its own transaction. The last day ends now and gets only its share of the rows.
WITH days AS (
    SELECT day, least(day + interval '1 day', now()) AS day_end,
           round(:per_day * extract(epoch FROM least(day + interval '1 day', now()) - day) / 86400)::int AS n
    FROM (SELECT date_bin('1 day', now(), TIMESTAMPTZ 'epoch') - d * interval '1 day' AS day FROM generate_series(:days, 0, -1) d) s
)
SELECT stmt FROM (
    SELECT day, 1 AS ord, format('SELECT pg_temp.perf_rows(%L, %L, %s, %L)', day, day_end, n, '00000000-0000-4000-8000-0000000000b1') AS stmt FROM days
    UNION ALL
    SELECT day, 2, format('SELECT pg_temp.perf_rows(%L, %L, %s, %L)', day, day_end, n / 10, '00000000-0000-4000-8000-0000000000b2') FROM days
    UNION ALL
    SELECT day, 3, 'SELECT compress_chunk(c, if_not_compressed => true) FROM show_chunks(''waf_decisions'', older_than => interval ''1 day'') c' FROM days
) s ORDER BY day, ord
\gexec

VACUUM (ANALYZE) waf_decisions;
SELECT count(*) AS decisions, min(recorded_at), max(recorded_at), count(DISTINCT app_id) AS apps FROM waf_decisions;
