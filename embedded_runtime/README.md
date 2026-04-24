# Qypha Embedded Runtime Layer

Bu klasor, OpenClaw snapshot'indan Qypha icine fiziksel olarak tasinmis
embedded runtime kodlari icin ayrilmistir.

Kural:

- `vendor/openclaw_snapshot/upstream/openclaw` sadece referans snapshot'tir
- calisan / import edilen kod bu klasore tasinir
- burada OpenClaw runtime motorlari korunur
- Qypha tarafinda sadece baglanti, supervision ve policy entegrasyonu
  yazilir

Ilk tasinacak capability sirası:

1. provider
2. research
3. browser
4. document
5. memory
6. os

Portable runtime notu:

- Python tabanli bundled MCP server'lar icin global `python` zorunlu degildir
- `npm run bootstrap:bundled-python` pinlenmis portable Python runtime'i repo icine indirir
- `npm run bootstrap:bundled-git` portable `git` runtime'ini repo icine indirir
- `npm run bootstrap:bundled-playwright` Chromium'u aktif platform icin repo icine indirir
- `npm run build:embedded-worker` bu bootstrap adimini otomatik calistirir
- launcher'lar once repo icindeki bundled Python'i kullanir, sonra opsiyonel sistem override'larina bakar
