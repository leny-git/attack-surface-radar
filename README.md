<p align="center">
  <pre align="center">
 █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
███████║   ██║      ██║   ███████║██║     █████═╝ 
██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
   ██████╗ ██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗
   ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
   ██████╔╝██║   ██║██████╔╝█████╗  ███████║██║     █████╗  
   ██╔══██╗██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝  
   ██║  ██║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝
  </pre>
</p>

<p align="center">
  <b>⚡ Yeni Nesil Harici Saldırı Yüzeyi Yönetimi (EASM) ve Pasif OSINT Keşif Platformu</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Dependencies-ZERO%20(Standart%20Lib)-success?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Type-%25100%20Passive%20OSINT-orange?style=for-the-badge" />
</p>

---

## 🎯 Nedir?

**Attack Surface Radar**, hedef alan adının (domain) internet üzerindeki tüm dijital ayak izini ve görünür saldırı yüzeyini **tamamen yasal ve pasif** yöntemlerle ortaya çıkaran bir keşif aracıdır.

Hedef sunucuya **asla doğrudan aktif port taraması yapmaz**; yalnızca kamuya açık SSL şeffaflık loglarını, DoH (DNS-over-HTTPS) altyapısını ve Shodan InternetDB verilerini kullanarak hedefi haritalandırır.

---

## ✨ Öne Çıkan Yetenekler

| Modül | Açıklama |
| :--- | :--- |
| 📜 **crt.sh Subdomain Keşfi** | SSL/TLS sertifika kayıtlarından unutulmuş `dev`, `admin`, `api`, `test` alt adreslerini yakalar. |
| ⚡ **Paralel DoH Çözümleme** | Google DNS-over-HTTPS ile A ve CNAME kayıtlarını saniyeler içinde çözer. |
| 🛡️ **Shodan InternetDB** | Açık IP adreslerinin açık portlarını, servislerini ve bilinen CVE zafiyetlerini pasif çeker. |
| 📧 **E-Posta Güvenlik Testi** | SPF ve DMARC kayıtlarını denetler; alan adının taklit (phishing/spoofing) riskini raporlar. |
| 🌐 **İnteraktif Ağ Grafiği** | `Domain ➔ Subdomain ➔ IP ➔ Port` ilişkisini hareketli, modern bir HTML haritasına döker. |
| 🚀 **Sıfır Bağımlılık** | `pip install` gerektirmez. Saf Python ile her bilgisayarda tıkla-çalıştır mantığıyla çalışır. |

---

## 🚀 Hızlı Başlangıç & Kullanım

> ⚠️ **ÖNEMLİ UYARI (WinRAR / ZIP Kullananlar İçin):**  
> Dosyayı GitHub'dan ZIP olarak indirdiyseniz, **arşivin içindeyken doğrudan çalıştırmayın!**  
> ZIP dosyasına **sağ tıklayıp "Klasöre Çıkart / Buraya Ayıkla"** dedikten sonra çıkan klasörün içinden çalıştırın.

---

### Yöntem 1: Tıkla-Çalıştır (Kod Yazmadan)

1. Klasördeki **`run_scan.bat`** dosyasına çift tıklayın.
2. Taranacak domain adresini yazın:
   ```text
   Taranacak domaini yazin (ornek: example.com): spotify.com
   ```
3. Tarama bittiğinde HTML raporunuz otomatik olarak klasörde açılmaya hazır olacaktır!

---

### Yöntem 2: Terminal / Komut Satırı

```bash
# Temel Tarama
python radar.py hedefdomain.com

# Özel Rapor Dosyası İsmi Belirleme
python radar.py hedefdomain.com -o sirket_raporu.html

# Eşzamanlı İş Parçacığı (Hız) Ayarı (Varsayılan: 10)
python radar.py hedefdomain.com -t 25
```

---

## 🖥️ Terminal Önizlemesi

```text
============================================================
   ATTACK SURFACE RADAR - TARGET.COM
============================================================

[*] crt.sh sertifika logları sorgulanıyor: target.com...
[+] crt.sh: 38 adet benzersiz subdomain bulundu.
[*] 39 adres için DNS kayıtları çözümleniyor...
[+] Aktif IP'si bulunan 14 subdomain doğrulandı.
[+] Toplam 5 benzersiz IP tespit edildi.
[*] 5 IP için Shodan InternetDB pasif kayıtları taranıyor...
[*] E-posta güvenlik yapılandırması (SPF / DMARC) kontrol ediliyor...
[+] Tarama 4.12 saniyede tamamlandı. Risk Skoru: 40/100
[+] İnteraktif HTML Raporu oluşturuldu: report_target_com.html

[+] Raporu tarayıcında açmak için: start report_target_com.html
```

---

## 📊 İnteraktif Görsel HTML Raporu

Tarama tamamlandığında oluşturulan `report_<domain>.html` dosyası şunları sunar:

* **İnteraktif Ağ Grafiği (Vis.js):** Fare ile sürüklenebilen, yakınlaştırılabilen dinamik varlık ilişkileri (`Mavi: Domain`, `Mor: Subdomain`, `Sarı: IP`, `Kırmızı: Açık Portlar`).
* **Otomatik Risk Skoru (0-100):** Tespit edilen portlar, eksik DMARC ve CVE açıklarına göre otomatik risk puanlaması.
* **Varlık Tablosu:** Tüm aktif adreslerin IP'leri, açık portları ve kritiklik durumları.

---

## 📁 Proje Dizin Yapısı

```text
attack-surface-radar/
├── radar.py          # Çekirdek tarama ve raporlama motoru (Zero-dependency)
├── run_scan.bat      # Windows için tek tıkla çalıştırma aracı
├── README.md         # Detaylı proje dokümantasyonu
└── .gitignore        # Gereksiz dosyaların depoya yüklenmesini önleyen yapılandırma
```

---

## ⚖️ Yasal Uyarı & Lisans

Bu yazılım yalnızca sistem yöneticileri, siber güvenlik uzmanları ve izinli güvenlik denetimleri için geliştirilmiştir. Kamuya açık OSINT verilerini derler. Yazılımın kötüye kullanımından doğacak sorumluluk kullanıcıya aittir.

Bu proje **MIT Lisansı** ile lisanslanmıştır.

