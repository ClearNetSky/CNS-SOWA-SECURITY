# S.O.W.A Security Software

<p align="center">
  <img src="https://github.com/user-attachments/assets/2ee846c2-b6e7-449b-ab8f-c2d097acd82b" alt="S.O.W.A" width="200">
</p>

<p align="center">
  <a href="https://github.com/ClearNetSky/CNS-SOWA-SECURITY/releases"><img src="https://img.shields.io/github/v/release/AristarhUcolov/CNS-SOWA-SECURITY?color=blue&label=version" alt="Version"></a>
  <a href="https://github.com/ClearNetSky/CNS-SOWA-SECURITY/blob/main/LICENSE"><img src="https://img.shields.io/github/license/AristarhUcolov/CNS-SOWA-SECURITY" alt="License"></a>
  <a href="https://github.com/ClearNetSky/CNS-SOWA-SECURITY"><img src="https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go" alt="Go"></a>
  <a href="https://github.com/ClearNetSky/CNS-SOWA-SECURITY/stargazers"><img src="https://img.shields.io/github/stars/AristarhUcolov/CNS-SOWA-SECURITY?style=flat" alt="Stars"></a>
</p>

<p align="center">
  <a href="#-ru--Русский">🇷🇺 Русский</a> · <a href="#-en--english">🇬🇧 English</a>
</p>

---

# 🇷🇺 RU / Русский

## 🔐 S.O.W.A Security Software — DNS-защита и фильтрация

**S.O.W.A Security Software** — полнофункциональное программное обеспечение для DNS-фильтрации и защиты, разработанное организацией **C.N.S (Clear Net Sky)**. Работает как сетевой DNS-сервер, блокируя рекламу, трекеры, вредоносные сайты и нежелательный контент на уровне DNS-запросов для всех устройств в сети.

## ✨ Возможности

| Категория | Описание |
|-----------|----------|
| 🛡️ **Блокировка рекламы и трекеров** | 29+ категорий блокировочных списков (C.N.S S.O.W.A Blacklist) |
| 🔒 **Зашифрованный DNS** | DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNSCrypt |
| 🔍 **Безопасный поиск** | Принудительный Safe Search на всех поисковиках (Google, Bing, Yandex, DuckDuckGo, Yahoo, YouTube, Ecosia, StartPage, Brave) |
| 👨‍👩‍👧‍👦 **Родительский контроль** | Блокировка контента для взрослых по категориям |
| 🌐 **DHCP-сервер** | Встроенный DHCP для автоматической настройки DNS |
| 📊 **Журнал запросов** | Подробная статистика DNS-запросов с WHOIS-информацией |
| 💻 **Веб-интерфейс** | Современная панель управления в стиле C.N.S с тёмной/светлой темой |
| 📋 **Пользовательские правила** | Чёрные, белые списки и правила фильтрации (поддержка wildcards `\|\|*.domain.com^`) |
| 🔄 **DNS-перенаправление** | Перенаправление доменов на указанные IP-адреса или другие домены |
| 👤 **Per-device конфигурация** | Индивидуальные настройки для каждого устройства |
| 🔐 **Контроль доступа** | Разрешённые/запрещённые клиенты и Rate Limiting |
| 🌍 **IPv4 и IPv6** | Полная поддержка двойного стека |
| 📦 **Портативность** | Один EXE-файл, работает без установки |
| 🔄 **Авто-обновление** | Автоматическое обновление блокировочных списков |
| 💾 **Резервное копирование** | Экспорт/импорт настроек |

## 🚀 Быстрый старт

1. Скачайте `sowa-security.exe` из [Releases](https://github.com/ClearNetSky/CNS-SOWA-SECURITY/releases)
2. Запустите EXE файл (от имени администратора для DHCP)
3. Откройте браузер: `http://localhost:8080`
4. Настройте DNS вашего устройства на `127.0.0.1`

## 🔧 Сборка из исходников

```bash
git clone https://github.com/ClearNetSky/CNS-SOWA-SECURITY.git
cd CNS-SOWA-SECURITY
go mod tidy
go build -o build/sowa-security.exe ./cmd/sowa/
```

Или используйте `build.bat` на Windows.

## 📂 Структура проекта

```
├── cmd/sowa/               # Точка входа приложения
├── internal/
│   ├── api/                # REST API и веб-сервер
│   ├── auth/               # Аутентификация и сессии
│   ├── config/             # Конфигурация
│   ├── dhcp/               # DHCP-сервер
│   ├── dnsserver/          # DNS-сервер (UDP/TCP/DoH/DoT)
│   │   ├── server.go       # Основной DNS-сервер
│   │   ├── upstream.go     # Upstream DNS резолвер
│   │   └── encrypted.go    # Зашифрованный DNS
│   ├── filtering/          # Движок фильтрации
│   │   ├── engine.go       # Основной движок
│   │   └── safesearch.go   # Безопасный поиск
│   └── stats/              # Статистика и журнал запросов
├── web/                    # Веб-интерфейс (HTML/CSS/JS)
├── data/                   # Данные (списки, конфиг, статистика)
│   ├── blacklist/          # Кэш чёрных списков
│   ├── whitelist/          # Кэш белых списков
│   └── config/             # Конфигурация и статистика
└── build/                  # Скомпилированные файлы
```

## 🔗 Ссылки

- 🌐 [Сайт Clear Net Sky](https://clearnetsky.github.io/C.N.S-Clear.Net.Sky-S.O.W.A/)
- 📋 [DNS-списки блокировки (S.O.W.A Lists)](https://github.com/ClearNetSky/CNS-SOWA-DNS-BLACKLIST-FILTERING)
- 🔐 [S.O.W.A Security Software](https://github.com/ClearNetSky/CNS-SOWA-SECURITY)

## 🙏 Благодарности

Этот проект стал возможен благодаря потрясающим open-source проектам и их авторам:

| Проект | Автор | Описание |
|--------|-------|----------|
| [Go](https://go.dev/) | Google | Язык программирования |
| [miekg/dns](https://github.com/miekg/dns) | **Miek Gieben** | DNS-библиотека для Go — основа нашего DNS-сервера |
| [Chart.js](https://www.chartjs.org/) | Chart.js Contributors | Библиотека графиков для веб-интерфейса |
| [Font Awesome](https://fontawesome.com/) | Fonticons, Inc. | Библиотека иконок |
| [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) | AdGuard Team | Вдохновение для архитектуры и UX |
| [Pi-hole](https://pi-hole.net/) | Pi-hole LLC | Пионер DNS-блокировки |

**Go-модули:**
- [`golang.org/x/net`](https://pkg.go.dev/golang.org/x/net) — расширенная сетевая поддержка
- [`golang.org/x/sync`](https://pkg.go.dev/golang.org/x/sync) — синхронизация горутин
- [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) — системные вызовы

## 📜 Лицензия

Данный проект распространяется под лицензией **GNU General Public License v3.0 (GPL-3.0)**.

Полный текст лицензии: [LICENSE](LICENSE)

- ✅ Свободное использование, модификация и распространение
- ✅ Обязательное указание авторства
- ✅ Открытый исходный код в производных работах
- ❌ Нельзя использовать в закрытом коммерческом ПО

## 👥 Команда

Разработано **C.N.S (Clear Net Sky)** совместно с **S.A** и **OpcoderZ-Security**.

---

<p align="center">
  <a href="#-en--english">🇬🇧 Switch to English ↓</a>
</p>

---

# 🇬🇧 EN / English

## 🔐 S.O.W.A Security Software — DNS Protection & Filtering

**S.O.W.A Security Software** — full-featured DNS filtering and protection software developed by **C.N.S (Clear Net Sky)** organization. It operates as a network DNS server, blocking ads, trackers, malware, and unwanted content at the DNS query level for all devices on the network.

## ✨ Features

| Category | Description |
|----------|-------------|
| 🛡️ **Ad & Tracker Blocking** | 29+ categories of blocklists (C.N.S S.O.W.A Blacklist) |
| 🔒 **Encrypted DNS** | DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNSCrypt |
| 🔍 **Safe Search** | Enforce Safe Search on all search engines (Google, Bing, Yandex, DuckDuckGo, Yahoo, YouTube, Ecosia, StartPage, Brave) |
| 👨‍👩‍👧‍👦 **Parental Control** | Block adult content by categories |
| 🌐 **Built-in DHCP Server** | Auto-configure DNS for network clients |
| 📊 **Query Log** | Detailed DNS query statistics with WHOIS information |
| 💻 **Web Interface** | Modern admin dashboard in C.N.S style with dark/light theme |
| 📋 **Custom Rules** | Blocklists, whitelists, and filtering rules (wildcard support `\|\|*.domain.com^`) |
| 🔄 **DNS Rewrites** | Redirect domains to specified IP addresses or other domains |
| 👤 **Per-client Configuration** | Individual settings per device |
| 🔐 **Access Control** | Allowed/disallowed clients and Rate Limiting |
| 🌍 **IPv4 and IPv6** | Full dual-stack support |
| 📦 **Portable** | Single EXE, no installation required |
| 🔄 **Auto-Update** | Automatic blocklist updates with configurable interval |
| 💾 **Backup & Restore** | Export/import configuration |

## 🚀 Quick Start

1. Download `sowa-security.exe` from [Releases](https://github.com/ClearNetSky/CNS-SOWA-SECURITY/releases)
2. Run the EXE file (as administrator for DHCP)
3. Open browser: `http://localhost:8080`
4. Set your device's DNS to `127.0.0.1`

## 🔧 Build from Source

```bash
git clone https://github.com/ClearNetSky/CNS-SOWA-SECURITY.git
cd CNS-SOWA-SECURITY
go mod tidy
go build -o build/sowa-security.exe ./cmd/sowa/
```

Or use `build.bat` on Windows.

## 📂 Project Structure

```
├── cmd/sowa/               # Application entry point
├── internal/
│   ├── api/                # REST API and web server
│   ├── auth/               # Authentication and sessions
│   ├── config/             # Configuration
│   ├── dhcp/               # DHCP server
│   ├── dnsserver/          # DNS server (UDP/TCP/DoH/DoT)
│   │   ├── server.go       # Main DNS server
│   │   ├── upstream.go     # Upstream DNS resolver
│   │   └── encrypted.go    # Encrypted DNS
│   ├── filtering/          # Filtering engine
│   │   ├── engine.go       # Main engine
│   │   └── safesearch.go   # Safe Search
│   └── stats/              # Statistics and query log
├── web/                    # Web interface (HTML/CSS/JS)
├── data/                   # Data (lists, config, statistics)
│   ├── blacklist/          # Blocklist cache
│   ├── whitelist/          # Whitelist cache
│   └── config/             # Configuration and statistics
└── build/                  # Compiled files
```

## 🔗 Links

- 🌐 [Clear Net Sky Website](https://clearnetsky.github.io/C.N.S-Clear.Net.Sky-S.O.W.A/)
- 📋 [DNS Blacklist Filtering (S.O.W.A Lists)](https://github.com/ClearNetSky/CNS-SOWA-DNS-BLACKLIST-FILTERING)
- 🔐 [S.O.W.A Security Software](https://github.com/ClearNetSky/CNS-SOWA-SECURITY)

## 🙏 Acknowledgments

This project was made possible by the amazing open-source projects and their authors:

| Project | Author | Description |
|---------|--------|-------------|
| [Go](https://go.dev/) | Google | Programming language |
| [miekg/dns](https://github.com/miekg/dns) | **Miek Gieben** | DNS library for Go — the foundation of our DNS server |
| [Chart.js](https://www.chartjs.org/) | Chart.js Contributors | Charting library for the web interface |
| [Font Awesome](https://fontawesome.com/) | Fonticons, Inc. | Icon library |
| [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) | AdGuard Team | Inspiration for architecture and UX |
| [Pi-hole](https://pi-hole.net/) | Pi-hole LLC | DNS blocking pioneer |

**Go Modules:**
- [`golang.org/x/net`](https://pkg.go.dev/golang.org/x/net) — extended networking support
- [`golang.org/x/sync`](https://pkg.go.dev/golang.org/x/sync) — goroutine synchronization
- [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) — system calls

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

Full license text: [LICENSE](LICENSE)

- ✅ Free to use, modify, and distribute
- ✅ Attribution required
- ✅ Source code must remain open in derivative works
- ❌ Cannot be used in proprietary commercial software

## 👥 Team

Developed by **C.N.S (Clear Net Sky)** in collaboration with **S.A** and **OpcoderZ-Security**.

---

<p align="center">
  <a href="#-ru--Русский">🇷🇺 Переключить на Русский ↑</a>
</p>

---

<p align="center">
  <strong>S.O.W.A Security Software</strong> — protecting your network at the DNS level
  <br><br>
  <em>© 2024-2026 C.N.S (Clear Net Sky). All rights reserved.</em>
</p>
