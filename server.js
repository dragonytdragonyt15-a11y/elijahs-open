import express from 'express';
import { Agent, request } from 'undici';
import dns from 'node:dns';
import { BlockList, isIP } from 'node:net';
import { randomBytes, timingSafeEqual } from 'node:crypto';

// Keeps the server itself safe: never lets the page reach private/internal addresses.
const blocked = new BlockList();
[['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.168.0.0',16],['224.0.0.0',4],['240.0.0.0',4]]
  .forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv4'));
[['::',128],['::1',128],['::ffff:0:0',96],['fc00::',7],['fe80::',10],['ff00::',8]]
  .forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv6'));
const bad = (ip) => { const f = isIP(ip); return !f || blocked.check(ip, f === 4 ? 'ipv4' : 'ipv6'); };

const agent = new Agent({ connect: { lookup(host, opts, cb) {
  dns.lookup(host, { ...opts, all: true }, (e, a) => {
    if (e) return cb(e);
    if (!a.length || a.some((x) => bad(x.address))) return cb(new Error('blocked'));
    opts.all ? cb(null, a) : cb(null, a[0].address, a[0].family);
  });
} } });

function parse(input) {
  let s = input.trim();
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  const u = new URL(s);
  const h = u.hostname.replace(/^\[|\]$/g, '');
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('scheme');
  if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) throw new Error('port');
  if ((isIP(h) && bad(h)) || h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) throw new Error('blocked');
  return u;
}

const msg = (res, text) => res.status(502).type('html')
  .send(`<body style="font:16px system-ui;padding:40px;color:#444"><h3>${text}</h3></body>`);

const PASSWORD = process.env.PASSWORD || '';
const HOST = process.env.HOST || '127.0.0.1';
if (HOST !== '127.0.0.1' && !PASSWORD) { console.error('Set a PASSWORD before putting this on the web.'); process.exit(1); }
const TOKEN = randomBytes(24).toString('hex');
const fails = new Map();

const app = express();
app.set('trust proxy', 1);
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "public")));

app.get('/status', (_req, res) => res.json({ locked: !!PASSWORD }));
app.post('/login', express.json({ limit: '1kb' }), (req, res) => {
  if (!PASSWORD) return res.json({ token: '' });
  const f = fails.get(req.ip) || { n: 0, t: 0 };
  if (Date.now() - f.t >= 15 * 60_000) f.n = 0;
  if (f.n >= 5) return res.status(429).json({ error: 'Too many tries. Wait 15 minutes.' });
  const a = Buffer.from(String(req.body?.password || '')), b = Buffer.from(PASSWORD);
  if (a.length === b.length && timingSafeEqual(a, b)) { fails.delete(req.ip); return res.json({ token: TOKEN }); }
  fails.set(req.ip, { n: f.n + 1, t: Date.now() });
  res.status(401).json({ error: 'Wrong password.' });
});

app.get('/page', async (req, res) => {
  if (PASSWORD && req.query.k !== TOKEN)
    return res.status(401).type('html').send('<body style="font:16px system-ui;padding:40px"><h3>Session expired. Reload the page and enter your password.</h3><script>parent.postMessage("expired","*")</script></body>');
  try {
    let url = parse(String(req.query.url || ''));
    for (let i = 0; i < 5; i++) {
      const r = await request(url, { dispatcher: agent, signal: AbortSignal.timeout(12000),
        headers: { 'user-agent': 'Mozilla/5.0 (compatible; SimpleOpen/1.0)', accept: 'text/html,*/*;q=0.8' } });
      if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
        await r.body.dump();
        url = parse(new URL(String(r.headers.location), url).href);
        continue;
      }
      if (!/html/i.test(String(r.headers['content-type'] || ''))) {
        await r.body.dump();
        return msg(res, "That isn't a web page (downloads aren't supported).");
      }
      const chunks = []; let n = 0;
      for await (const c of r.body) {
        n += c.length;
        if (n > 5_000_000) { r.body.destroy(); return msg(res, 'That page is too large.'); }
        chunks.push(c);
      }
      const origin = `${req.protocol}://${req.get('host')}`;
      const inject = `<base href="${url.href}"><script>
        var O=${JSON.stringify(origin)},K=${JSON.stringify(String(req.query.k || ''))};
        document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[href]');
          if(!a||a.getAttribute('href').charAt(0)==='#')return;e.preventDefault();
          location.href=O+'/page?k='+encodeURIComponent(K)+'&url='+encodeURIComponent(a.href)},true);
        document.addEventListener('submit',function(e){e.preventDefault();var f=e.target;
          if((f.method||'get').toLowerCase()!=='get')return;
          var u=new URL(f.getAttribute('action')||'',document.baseURI);
          new FormData(f).forEach(function(v,k){u.searchParams.set(k,v)});
          location.href=O+'/page?k='+encodeURIComponent(K)+'&url='+encodeURIComponent(u.href)},true);
      </script>`;
      let html = Buffer.concat(chunks).toString('utf8');
      html = /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, (m) => m + inject) : inject + html;
      return res.set({
        'content-type': 'text/html; charset=utf-8',
        'content-security-policy': 'sandbox allow-scripts allow-forms',
        'referrer-policy': 'no-referrer',
      }).send(html);
    }
    msg(res, 'Too many redirects.');
  } catch {
    msg(res, "Couldn't open that site. Check the address and try again.");
  }
});

app.listen(process.env.PORT || 3000, HOST, () => console.log('Running on port ' + (process.env.PORT || 3000)));
