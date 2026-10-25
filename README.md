# 🛡️ Attack Surface Radar (ASR)

> **Modern, %100 Pasif ve Harici Kütüphane Gerektirmeyen Dış Saldırı Yüzeyi (EASM) & OSINT Aracı**

Attack Surface Radar, verilen bir domain adresinin internete açık dijital ayak izini ve saldırı yüzeyini **tamamen pasif yöntemlerle** haritalandırır. Hedef sisteme doğrudan aktif port taraması yapmaz; sadece kamuya açık şeffaflık loglarını ve indeksleri sorgular.

---

## 🚀 Özellikler

* **⚡ Sıfır Bağımlılık (Zero Dependencies):** Harici hiçbir kütüphane (`pip`) gerektirmez. Saf Python 3 standart kütüphanesi ile çalışır.
* **📜 crt.sh Entegrasyonu:** SSL/TLS Certificate Transparency (Şeffaflık) kayıtlarından unutulmuş alt alan adlarını (subdomain) yakalar.
* **🌐 Google DNS-over-HTTPS (DoH):** Hızlı ve paralel DNS çözümlemesi ile A ve CNAME kayıtlarını tespit eder.
* **🔍 Shodan InternetDB:** Bulunan IP'ler için Shodan'ın kamuya açık API'sinden açık portları ve bilinen zafiyetleri (CVE) çeker.
* **📧 E-posta Güvenlik Analizi:** SPF ve DMARC kayıtlarını inceleyerek spoofing / phishing riskini puanlar.
* **📊 İnteraktif Görsel Ağ Raporu:** Vis.js tabanlı, tek dosyalık HTML raporu üretir (`Domain ➔ Subdomain ➔ IP ➔ Port` ilişkisini interaktif düğüm grafiği olarak çizer).

---

## 🛠️ Kullanım

```bash
python radar.py hedefsite.com
```

---

## ⚖️ Yasal Uyarı

Bu araç yalnızca güvenlik denetimleri, zafiyet yönetimi ve eğitim amacıyla hazırlanmıştır. %100 pasif açık kaynak istihbaratı (OSINT) yöntemleriyle çalışır.
