# Changelog

## 1.0.1

- Ready-to-run downloads: `Panoptes-windows-x64.zip` and `Panoptes-linux-x64.tar.gz` contain the
  desktop app, the terminal tool and a private Python runtime. Nothing else to install.
- Windows: `Panoptes.exe` (desktop) and `panoptes-cli.exe` (terminal), plus `Add shortcuts.cmd`.
- Linux: `panoptes-gui` and `panoptes` launchers, plus `install.sh` for a menu entry and PATH links.
- The desktop app now depends on PySide6-Essentials instead of the full PySide6, which makes every
  install much smaller.

## 1.0.0 - first public release

- Panoptes is now public, open source under the GPL-3.0, and free forever.
- Linux support: `install.sh` installs into its own virtual environment, adds the `panoptes` and
  `panoptes-gui` commands and an applications-menu entry.
- Built-in Tor now uses the system `tor` binary on Linux and macOS (private instance, private torrc).
- The Light resource profile lowers process priority on Linux too (`nice`).
- CI checks every change on Windows and Linux.

## 0.5

- **Trust model.** Every lead carries a trust score inherited from the evidence that produced it. Guesses
  (generated usernames, single-token aliases, unverified emails) are listed but not followed unless something
  independent ties them to the subject, so a common first name or nickname can't drag in strangers.
- **Site logins for anything.** Sites that hide profiles behind a login (Facebook, LinkedIn, …) are listed after
  each search. Paste a burner account's browser cookie per site in *Settings > Logins & sessions* (or
  `panoptes login add facebook.com "<cookie>"`). Each cookie is only ever sent to its own site.
- **Built-in Tor.** Dark-web search (Torch, Haystak, Ahmia's onion service) and OnionScan work immediately.
  Panoptes uses a running Tor Browser / tor service, or downloads the official Tor Expert Bundle once and
  runs it privately.
- **Public records:** US sex-offender registries (NSOPW + state registries), Federal Bureau of Prisons inmates,
  NPI healthcare providers (with practice addresses), FINRA BrokerCheck / SEC advisers, CourtListener court
  records (free token), ICIJ Offshore Leaks, USAspending, plus pre-filled US people-search lookups. US-only
  registries are skipped automatically when the subject is clearly elsewhere. Name matches stay low-confidence
  unless they line up with a place already tied to the subject.
- **Addresses.** Street addresses found in registrations, registries, profiles or photos appear in the
  overview. Network-operator, registrar and privacy-proxy addresses are excluded.
- **Resource profiles:** Light / Balanced / Heavy (`--profile`, or the *Resources* box). Light caps workers
  and image analysis and lowers process priority so you can keep working. It runs slower but checks the same
  sites, so it finds the same results.
- **Stopping keeps the results:** *Stop* still builds the full overview from everything found so far.
- **Images:** where-was-this-taken verdict for every image (GPS > written coordinates > OCR'd addresses >
  landmarks > AI estimates). Online visual geolocation via Picarta (`picarta_api_key`) or Claude vision;
  GeoCLIP is used only if you install it yourself (`pip install geoclip`, ~2 GB, offline). Image-match details
  show the matched image.
- **Service joins:** "email registered on Spotify/X/…" plus a matching handle → the likely profile URL.
- **More sites:** LinkedIn, Facebook, Quora, VK, OK.ru, Etsy, … and 45+ more adult/creator/link-in-bio
  platforms (1,645 standard / 11,640 full sites with `--nsfw`). Graph nodes can no longer be dragged.

## 0.4

- **Faster first results.** Sites are checked most-likely-first (learned from past searches). A quick
  7-second pass streams hits within seconds, then a thorough pass re-checks the slow and blocked sites.
  Sites that "find" any username are remembered and skipped from then on.
- **No more starvation.** Every source gets its own connection budget, and bulk scans share a ceiling, so
  GitHub and breach lookups can't be squeezed out by an 11,000-site scan.
- **Shared-handle awareness.** If a username belongs to several different people (conflicting real
  names), Panoptes only follows leads from accounts that are corroborated as the subject's.
- **Platform intel:** Duolingo, Codewars, LeetCode, Codeforces, Lichess, Twitch, Docker Hub, Minecraft,
  Roblox, Bluesky, YouTube, Steam, npm, Gravatar and GitHub GPG/SSH keys contribute real names,
  locations, emails, avatars and links.
- **Email from a username:** guesses likely addresses and verifies them via Gravatar, Spotify and Duolingo.
  A guess is only followed when something ties it to the person (e.g. Duolingo returns this exact username).
- **Aliases & likely location:** display names that differ from the handle are tracked and followed when
  repeated. A "Likely country / city" is built from every location signal on the subject's own accounts.
- **Names, news & public records:** search-engine dorks (Brave / Google / SerpAPI with a key, Bing
  otherwise), Google News + GDELT, Wikipedia, ORCID, OpenAlex, Interpol, FBI wanted, US FEC donations.
  When a real name is established (≥90% or corroborated) it is searched too.
- **Images:** OCR (coordinates from Google Earth screenshots, signs, addresses, handles), automatic ExifTool,
  reverse image search that geolocates recognised landmarks, and optional **Claude vision** geolocation
  (`anthropic_api_key`). Selected findings show their images in the Details tab.
- **Maltego-style graph:** category clusters, drag/zoom, click to inspect, right-click transforms that
  extend the open case.
- **Target type `all`** tries every plausible reading of the input. Mixed-case usernames are re-checked in lowercase.
- **More sites:** +curated adult/creator, payment, gaming and dev-registry platforms (11,560 unique sites,
  180+ NSFW with `--nsfw`).
