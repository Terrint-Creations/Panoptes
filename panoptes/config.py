"""User configuration: API keys, account logins/sessions, and network settings.

Stored in ~/.panoptes/config.toml. Every key can be overridden with an environment variable
named PANOPTES_<KEY> (uppercased). Everything is optional: sources that need a missing key are
skipped, and login-based sources simply don't run until a session is provided.
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

DATA_DIR = Path(os.environ.get("PANOPTES_HOME", Path.home() / ".panoptes"))
CACHE_DIR = DATA_DIR / "cache"
CONFIG_FILE = DATA_DIR / "config.toml"

# group -> key -> (description, how to get it)
KEY_GROUPS: dict[str, dict[str, tuple[str, str]]] = {
    "API keys": {
        "hibp_api_key": ("Have I Been Pwned - breach lookups for emails", "haveibeenpwned.com/API/Key"),
        "github_token": ("GitHub token - higher API rate limits", "github.com/settings/tokens (no scopes needed)"),
        "anthropic_api_key": ("Claude API - AI image analysis & visual geolocation of photos/screenshots",
                              "platform.claude.com > API keys (billed per use)"),
        "brave_api_key": ("Brave Search API - reliable search-engine results (free 2,000/month)",
                          "api-dashboard.search.brave.com > Subscriptions > Free"),
        "google_cse_key": ("Google Programmable Search API key (100 free searches/day)",
                           "developers.google.com/custom-search/v1/overview"),
        "google_cse_cx": ("Google Programmable Search engine ID (cx) - set to search the whole web",
                          "programmablesearchengine.google.com"),
        "serpapi_key": ("SerpAPI - Google results + Google Lens reverse image search", "serpapi.com (free tier)"),
        "spotify_client_id": ("Spotify app client id - reads Spotify profiles (name, picture)",
                              "developer.spotify.com/dashboard > Create app (free)"),
        "spotify_client_secret": ("Spotify app client secret", "Same app's settings page"),
        "opencorporates_api_token": ("OpenCorporates - company registries worldwide", "opencorporates.com/api_accounts/new"),
        "companies_house_api_key": ("UK Companies House - companies and officers (people)", "developer.company-information.service.gov.uk"),
        "picarta_api_key": ("Picarta - online AI photo geolocation (where was this picture taken?)",
                            "picarta.ai > API (free trial on request)"),
        "courtlistener_token": ("CourtListener token - US court opinions & dockets naming a person",
                                "courtlistener.com > sign up (free) > Profile > API"),
        "opensanctions_api_key": ("OpenSanctions - sanctions / PEP screening", "opensanctions.org/api"),
        "otx_api_key": ("AlienVault OTX - passive-DNS subdomains", "otx.alienvault.com (free account)"),
        "ipinfo_token": ("ipinfo.io - more IP geolocation detail", "ipinfo.io/signup"),
        "numverify_api_key": ("numverify / APILayer - live phone carrier lookups", "numverify.com"),
        "wigle_api_name": ("WiGLE API name - Wi-Fi network (BSSID/SSID) geolocation", "wigle.net/account"),
        "wigle_api_token": ("WiGLE API token", "wigle.net/account"),
    },
    "Logins & sessions": {
        "instagram_sessionid": ("Instagram 'sessionid' cookie - full profiles, hidden contact info (Toutatis), posts",
                                "Log in on instagram.com > DevTools > Application > Cookies > sessionid. Use a burner account."),
        "x_auth_token": ("X/Twitter 'auth_token' cookie - more reliable profile/tweet access",
                         "Log in on x.com > DevTools > Application > Cookies > auth_token"),
        "x_ct0": ("X/Twitter 'ct0' cookie (pairs with auth_token)", "Same place as auth_token"),
        "reddit_client_id": ("Reddit app client id - profile, subreddits, activity-hour timezone",
                             "reddit.com/prefs/apps > create 'script' app"),
        "reddit_client_secret": ("Reddit app secret", "Shown on the same app page"),
    },
    "Network": {
        "proxy": ("HTTP/SOCKS proxy for all requests", "e.g. http://127.0.0.1:8080"),
        "tor_proxy": ("Tor SOCKS proxy - enables .onion scanning (OnionScan-style)",
                      "Run Tor Browser (socks5://127.0.0.1:9150) or tor service (socks5://127.0.0.1:9050)"),
        "default_region": ("Default country for phone numbers without +prefix", "e.g. US, GB, DE"),
    },
}
KNOWN_KEYS: dict[str, str] = {k: v[0] for group in KEY_GROUPS.values() for k, v in group.items()}
SECRET_KEYS = {k for g in ("API keys", "Logins & sessions") for k in KEY_GROUPS[g]}


class Config:
    def __init__(self, values: dict[str, str] | None = None):
        self._values: dict[str, str] = dict(values or {})

    @classmethod
    def load(cls) -> "Config":
        values: dict[str, str] = {}
        if CONFIG_FILE.exists():
            try:
                with CONFIG_FILE.open("rb") as fh:
                    values = {k: str(v) for k, v in tomllib.load(fh).items()}
            except (OSError, tomllib.TOMLDecodeError):
                values = {}
        return cls(values)

    def get(self, key: str, default: str | None = None) -> str | None:
        env = os.environ.get(f"PANOPTES_{key.upper()}")
        if env:
            return env
        value = self._values.get(key)
        return value if value else default

    def set(self, key: str, value: str | None) -> None:
        if value:
            self._values[key] = value
        else:
            self._values.pop(key, None)

    def items(self) -> dict[str, str]:
        return dict(self._values)

    def save(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        lines = ["# Panoptes configuration\n"]
        for key, value in sorted(self._values.items()):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key} = "{escaped}"\n')
        CONFIG_FILE.write_text("".join(lines), encoding="utf-8")
