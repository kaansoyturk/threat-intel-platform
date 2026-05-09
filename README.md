# 🔴 Threat Intelligence Platform

VirusTotal, AbuseIPDB ve Shodan entegrasyonuyla IP, domain ve CVE analizi yapan tehdit istihbarat platformu.

## Ne Yapıyor?

- IP adresi analizi — 3 farklı kaynaktan tehdit skoru üretir
- Domain analizi — zararlı domain tespiti
- CVE takibi — NVD veritabanından gerçek zamanlı açık araması
- Otomatik tip tespiti — IP mi, domain mi, CVE mi otomatik anlar

## Veri Kaynakları

- VirusTotal — 70+ antivirüs motoru ile analiz
- AbuseIPDB — abuse raporu ve TOR/VPN tespiti
- Shodan — açık port ve servis tespiti
- NVD — NIST CVE veritabanı

## Teknolojiler

- Python 3
- Flask — Web arayüzü
- requests — API entegrasyonları
- python-dotenv — Güvenli API key yönetimi

## Kurulum

    git clone https://github.com/kaansoyturk/threat-intel-platform.git
    cd threat-intel-platform
    python3 -m venv venv
    source venv/bin/activate
    pip3 install flask requests python-dotenv colorama reportlab sqlalchemy

## API Key'ler

.env dosyası oluştur:

    VIRUSTOTAL_API_KEY=api_key
    ABUSEIPDB_API_KEY=api_key
    SHODAN_API_KEY=api_key

API key'leri ücretsiz almak için:
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- Shodan: https://account.shodan.io/register

## Kullanim

    python3 app.py

Tarayicide ac: http://localhost:5056

## Özellikler

- IP analizi — tehdit skoru, TOR/VPN tespiti, açık portlar
- Domain analizi — zararlı domain tespiti, DNS çözümleme
- CVE arama — keyword ile NVD veritabanında arama
- Son CVE'ler — son 7 günün kritik açıkları
- Otomatik tip tespiti

## Gelistirici

Kaan Soyturk — github.com/kaansoyturk