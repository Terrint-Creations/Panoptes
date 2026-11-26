<p align="center"><img src="packaging/panoptes.svg" width="96" alt="Panoptes eye"></p>

<h1 align="center">Panoptes</h1>

<p align="center"><b>One search. Every source. Merged, verified, followed.</b><br>
A free and open source OSINT tool for Windows and Linux.</p>

<p align="center">
<a href="https://panoptes.terrint.com">Website</a> ·
<a href="https://github.com/Terrint-Creations/Panoptes/releases/latest">Download</a> ·
<a href="#install">Install</a> ·
<a href="CONTRIBUTING.md">Contribute</a> ·
<a href="https://panoptes.terrint.com/#join">Join the project</a>
</p>

---

In Greek myth, Argus Panoptes was the giant with a hundred eyes. Some of them were always open, so
nothing escaped him. This tool is built the same way: many eyes, each one an OSINT technique, all
watching the same subject at once.

Panoptes combines original code with the ideas and data behind well known open source OSINT tools
(Sherlock, WhatsMyName, Maigret, Holehe, PhoneInfoga, theHarvester, SpiderFoot and many more). It
doesn't just run them side by side. It re-implements and merges what they do so they cover each
other's blind spots: one search fans out to every relevant capability, duplicate results are merged,
findings are cross-checked, each one gets a confidence score, and new leads are followed
automatically. Everything ends up in one case you can explore, graph and export.

Use it as a desktop app or from the terminal.

## Free forever

Panoptes is free and open source software, released under the
[GNU General Public License v3.0](LICENSE). It will never have a paid tier, a premium edition or a
locked feature. Anyone can use it, study it, change it and share it, and anyone can fork it and take
it in their own direction. The GPL keeps every published version of Panoptes and its derivatives
open for everyone who comes after.

## Install

**Ready-to-run apps** (no Python or anything else needed). Download from
[panoptes.terrint.com](https://www.panoptes.terrint.com/#download) or the
[latest release](https://github.com/Terrint-Creations/Panoptes/releases/latest):

| | Download | Run |
|---|---|---|
| **Windows 10/11** (64-bit) | `Panoptes-windows-x64.zip` | Unzip, open `Panoptes.exe` (desktop) or `panoptes-cli.exe` (terminal). `Add shortcuts.cmd` adds Desktop and Start Menu shortcuts. |
| **Linux** (x86-64) | `Panoptes-linux-x64.tar.gz` | Unpack, run `./panoptes/panoptes-gui` or `./panoptes/panoptes`. `./panoptes/install.sh` adds a menu entry and puts both on your PATH. |

Each download contains only the app and a private Python runtime. Windows may show a SmartScreen
warning the first time because Panoptes isn't code-signed: choose *More info*, then *Run anyway*.
For the dark-web sources on Linux, install Tor (`sudo apt install tor`).

**From source.** Needs Python 3.11 or newer. Clone this repository, then:

- Windows: double-click `install.bat`. It installs Panoptes into your Python, builds a small
  `Panoptes.exe` launcher and adds Desktop and Start Menu shortcuts.
- Linux: run `./install.sh` (or `./install.sh --minimal` for the terminal only). It uses its own
  virtual environment in `~/.local/share/panoptes` and adds an applications-menu entry.

**Any platform, by hand**

```bash
python -m pip install ".[all]"      # or ".[gui]" for just the desktop app, or "." for the terminal only
panoptes update                     # download and merge the site databases (refreshed weekly)
```

Optional extras: `gui`, `email` (Holehe), `phone` (Ignorant), `faces`, `ocr`, `ai`, `all`.

## Capabilities

| Capability | Merged from / inspired by |
|---|---|
| **Username → accounts** | Sherlock + WhatsMyName + Maigret + social-analyzer databases → ~11.4k-site catalog. Every database's rule votes on each site, and a random-username check removes false positives |
| **Site discovery** (deep search) | Links on found profiles that contain the username become new site templates. They're validated, checked for every username in the case, and **saved so future searches check them too** |
| **Alt-account finder** | Variations of the handle (and name-based handles) on the same platforms. Reported only with evidence: same picture, an explicit @mention, the same bio link |
| **Profile deep-parse** | Blackbird/Maigret-style page metadata; Keybase proofs, Mastodon, HN, GitLab, Dev.to, Chess.com APIs; Linktree-style link pages |
| **X / Twitter** | twint forks / birdwatcher: profile, recent tweets, who they mention, shared links, posting-hour timezone (no login; cookies optional) |
| **Instagram** | Toutatis + Instaloader: profile, business contacts, post locations/mentions/tags; with a session, hidden contact fields + obfuscated recovery email/phone |
| **TikTok, Telegram, Reddit** | Public profile parsing; Reddit (app keys) adds top communities and an activity-hour timezone |
| **Email → accounts** | Holehe (121 modules) + Blackbird email checks; Gravatar, GitHub, PGP keyservers, public Google Calendar (GHunt-style) |
| **Phone** | PhoneInfoga + Moriarty: numbering-plan analysis, **Ignorant** (Instagram / Snapchat / Amazon registration), numverify, search leads |
| **Breaches & leaks** | HIBP + XposedOrNot + LeakCheck + Hudson Rock infostealer logs + COMB (presence only, passwords never stored) |
| **Reverse image search** | Yandex (URL or uploaded file - **local photos are sent to Yandex**; turn off with `--no-reverse-image`), Google Lens via SerpAPI, plus TinEye / Bing / PimEyes / FaceCheck.ID / Search4faces / Lenso links |
| **Facial recognition** | Local OpenCV YuNet + SFace: faces in target photos matched against every collected profile picture |
| **Avatar matching** | Perceptual hashes link accounts that use the same picture, even under different usernames |
| **File & image metadata** | ExifTool-style EXIF/GPS, PDF/Office authors, hashes; full `exiftool` dump if installed |
| **GEOINT** | GEOINT toolkits / Geo-Sleuth / SunCalc: geocoding, nearby landmarks, time zone, elevation, sun position & shadows, historical weather at a photo's capture time, satellite/street-level links, WiGLE Wi-Fi geolocation |
| **Companies & power networks** | OpenCorporates, GLEIF, SEC EDGAR, UK Companies House (officers + appointments), OpenSanctions, LittleSis (the data behind **Oligrapher**) |
| **Domains** | Amass/Subfinder (8 passive datasets + brute force + AXFR + resolution), theHarvester/Photon/Metagoofil crawling + document metadata, gau historical URLs, dnstwist lookalikes, TLS, tracking IDs, Shodan favicon hash |
| **IPs** | 3-provider geolocation vote, RDAP, Shodan InternetDB, reverse DNS, Tor / GreyNoise / DNSBL / RIPEstat |
| **Dark web** | OnionScan-style .onion audits through Tor (status pages, open dirs, clearnet leaks, tracking IDs, wallets) + Ahmia index search |
| **Namechk** | Registered domains named after the username |
| **Crypto** | Bitcoin & Ethereum wallet activity |
| **Correlation** | SpiderFoot-style rules: identity summary, severity-rated insights, exposure score |
| **Cases & export** | Recon-ng-style saved cases; HTML (with relationship graph), JSON, CSV, STIX 2.1 for OpenCTI/MISP |

Not included: **Snoop's** site database is deliberately encrypted, so its coverage comes from the
other four open databases instead.

### Cooperative mode (sources helping each other)

Sources publish what they learn to a shared knowledge base, and other sources use it, but only
under strict rules:
- A fact is usable only if **you supplied it**, a source is ≥85% sure of it, or **two independent
  sources** agree on it.
- Facts never create findings. They only raise the confidence of a finding that *independently* contains
  them (e.g. a profile whose bio names the confirmed email). They can also flag a profile whose name
  contradicts the confirmed one, and that profile's leads aren't followed.
- A fact can't corroborate the finding it came from. Every adjustment is recorded on the finding
  (`corroborated_by` / `conflicts_with`).
- Hints flow to sources too: the confirmed name feeds the alt finder, and the subject's country feeds phone parsing.

Turn it off with `--no-coop` or in **Capabilities ▾**.

### Reliability

- Every request has a hard wall-clock deadline, and each site gets a per-host concurrency limit.
- A source that goes quiet for 3 minutes is stopped, and its results so far are kept.
- The GUI shows each running source's elapsed time.
- Everything is logged to `~/.panoptes/logs/panoptes.log` (**Tools ▸ Open log folder**).

## Desktop app

- **Full investigation…**: fill in everything you know (name, usernames, emails, phones, domains,
  IPs, companies, places, wallets, .onion sites, files and notes), choose capabilities, and launch.
- **Capabilities ▾**: toggle cooperative mode, face recognition, reverse image search, the alt finder,
  site learning and the dark web for quick searches.
- **Overview / Details / Graph**: identity summary and insights, per-finding evidence (incl. what
  corroborated it), and a relationship graph.
- **Tools ▸ Settings** has three tabs: API keys, **Logins & sessions** (Instagram, X, Reddit + a cookie for any other site) and Network (proxy, Tor).

## Terminal

```bash
panoptes search johndoe                         # type auto-detected
panoptes search jane@x.com -d 2 -o report.html
panoptes search "40.6892, -74.0445"             # GEOINT for coordinates
panoptes search "Acme Holdings Ltd"             # company
panoptes search photo.jpg                       # metadata, GPS → GEOINT, faces, reverse search
panoptes investigate                            # interactive full-investigation form
panoptes investigate --name "Jane Doe" -u jdoe -e jane@x.com --company "Acme Ltd" --location "Oslo" -f photo.jpg
panoptes config show / set instagram_sessionid XXXX
panoptes login add linkedin.com "li_at=…"     # any site that needs a login
panoptes search jdoe --profile light            # background-friendly
panoptes cases list | show 3 | export 3 case.stix.json
```

Toggles: `--no-coop --no-faces --no-reverse-image --no-alts --no-discovery --no-darkweb --passive`.

## Adding a source

Subclass `panoptes.sources.base.Source`, set `name`, `kinds` and `stage` (`primary`, `enrich` or
`late`), and implement `async def search(entity, ctx)` so it yields `Finding`s (add pivots to feed the deep
search). Optionally implement `finalize(ctx, report)` for global passes. Then register it in
`panoptes/sources/__init__.py`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## Responsible use

Panoptes only collects information that is already publicly available, but how you use it is your
responsibility. Only investigate people and organisations you have a legitimate reason and the legal
right to look into, for example yourself, your own organisation, an authorised engagement or
research with an ethical basis. Never use it to stalk, harass, dox or intimidate anyone. Use burner
accounts for site logins, and respect the terms and laws that apply to you.

## The project

Panoptes is a [Terrint Creations](https://www.terrint.com) project, maintained in the open.

- **Contribute:** open an issue or a pull request. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.
- **Join:** people who want to help steer Panoptes can ask to become project members through the
  form on [panoptes.terrint.com](https://panoptes.terrint.com/#join). See
  [GOVERNANCE.md](GOVERNANCE.md) for what membership means. Joining the Panoptes project does not make
  you part of Terrint Creations.
- **Fork:** you never need permission. Fork it and build whatever you like under the GPL.
- **Security issues:** see [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 Panoptes contributors.

Panoptes is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. It is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY. See [LICENSE](LICENSE) for details.

Panoptes downloads third-party site databases (Sherlock, WhatsMyName, Maigret, social-analyzer) at
runtime. They are not part of this repository and stay under their own licenses.
