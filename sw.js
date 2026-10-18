// GNP顧客ノート：アプリの画面をこの端末に保存して、圏外でも開けるようにする
// 画面を直したときは、この版の名前を変えると新しい画面に入れ替わります
const VERSION = "gnp-crm-v1";
const FILES = ["./", "./index.html", "./app.js", "./manifest.webmanifest", "./icon-180.png", "./icon-192.png", "./icon-512.png"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(FILES)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const req = e.request;
  const url = new URL(req.url);
  // スプレッドシートとの通信や、他のサイトへのアクセスには一切触れない（保存もしない）
  if (req.method !== "GET" || url.origin !== self.location.origin) return;
  e.respondWith(
    caches.open(VERSION).then(async cache => {
      const key = req.mode === "navigate" ? "./index.html" : req;
      const hit = await cache.match(key, { ignoreSearch: true });
      const net = fetch(req).then(res => {
        if (res.ok && res.type === "basic") cache.put(key, res.clone());
        return res;
      }).catch(() => null);
      if (hit) { e.waitUntil(net); return hit; }   // 保存してある画面をすぐ出し、裏で新しい画面を取りに行く
      return (await net) || new Response("圏外です", { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" } });
    })
  );
});
