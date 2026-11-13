# Ares

CyberWar Attack-Defense CTF üçün lokal sistem, Linux server və web tətbiqi yoxlama aləti.

## İşə salma

Windows və Linux dəstəklənir. Node.js 20.11+ və npm quraşdırıldıqdan sonra layihə qovluğunda işlət.

```sh
npm run deploy
```

Əmr ilkin yoxlamaları aparır və serveri başladır. Desktop mühitində panel avtomatik açılır. Standart ünvan `http://127.0.0.1:4517`-dir. Port tutulubsa terminalda göstərilən boş port istifadə olunur. Login panelində təyin etdiyin parolla daxil ol. Dayandırmaq üçün `Ctrl+C` bas.

Brauzersiz başlatmaq üçün `npm run deploy -- --no-open`, port seçmək üçün `npm run deploy -- --port 4518` istifadə et.

Uzaq serverin panelinə öz kompüterindən qoşulmaq üçün `ssh -L 4517:127.0.0.1:4517 user@SERVER_IP` istifadə et. Server başqa port göstəribsə tunelin son portunu ona uyğun dəyiş.

## İstifadə

Rejimi seç və **Start assessment** bas.

- **Local machine** - Windows və Linux portları, proqram versiyaları və təhlükəsizlik ayarları.
- **Remote Linux server (SSH)** - IP, port və username daxil et. SSH açarı və ya agent tələb olunur. Serverə əvvəl terminaldan qoşulub host fingerprint-i yoxla. Serverdə Python 3.10+, `ip`, `ss` və `dpkg-query`, `rpm` və ya `apk` olmalıdır.
- **Web application** - icazəli tətbiqin URL-ni daxil et. TLS, cookie, CORS, təhlükəsizlik başlıqları və xəta məlumatları yoxlanır. **SQLi and HTML reflection probes** seçimi URL parametrlərində SQL xəta, true/false SQLi və HTML əksolunma siqnallarını yoxlayır. Parametrli URL nümunəsi `http://lab.example/product?id=1`.

## AI ayarı

**AI settings** bölməsində OpenCode API key daxil edib **Save API key** bas. Standart model `deepseek-v4.1-flash`-dır. İstifadə üçün **External AI review** seçimini aktivləşdir.

Açar lokal `data/ai-settings.json` faylında açıq mətnlə saxlanır.

## Əsas qeydlər

- Web yoxlaması maksimum 10 GET sorğusu və sorğular arasında minimum 1 saniyə fasilə ilə işləyir.
- **Live CVE agent (OSV)** Debian, Ubuntu və Alpine paketlərini yoxlayır. Maksimum 24 sorğu və 24 saatlıq keş istifadə edir. OSV-yə distributiv, paket adı və versiyası göndərilir.
- Windows CVE yoxlaması kiçik offline bazaya əsaslanır.
- **Possible** tapıntılar əlavə təsdiq tələb edir. **Partial** natamam yoxlamanı, **Unknown** isə məlumatın əldə edilə bilmədiyini göstərir.
- AI risk və düzəliş izahı verir. **SAMPLE** sətrlər sintetik məlumatdır.
- Hesabatlar `data/assessments/`, loglar `data/ares.log` altında saxlanır.
