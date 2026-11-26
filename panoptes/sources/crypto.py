"""Cryptocurrency wallet lookups (Bitcoin via Blockstream, Ethereum via BlockCypher)."""
from __future__ import annotations

import datetime as dt
from urllib.parse import quote_plus

import httpx

from panoptes.detect import ETH_RE
from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source


class CryptoWalletSource(Source):
    name = "crypto-wallet"
    kinds = ("crypto",)
    description = "Wallet balance, activity and explorer links for Bitcoin and Ethereum addresses, plus web-mention leads"

    async def search(self, entity: Entity, ctx: Context):
        addr = entity.value.strip()
        base = dict(source=self.name, target=entity)
        try:
            if ETH_RE.match(addr):
                async for f in self._eth(addr, ctx, base):
                    yield f
            else:
                async for f in self._btc(addr, ctx, base):
                    yield f
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            ctx.log(f"crypto-wallet: {exc.__class__.__name__}", "warning")
        url = f"https://www.google.com/search?q={quote_plus(chr(34) + addr + chr(34))}"
        yield Finding(category="lead", title="Web mentions of address", value=url, url=url, confidence=0.5, **base)

    async def _btc(self, addr, ctx, base):
        d = await ctx.get_json(f"https://blockstream.info/api/address/{addr}", headers=API_HEADERS)
        cs = d["chain_stats"]
        bal = (cs["funded_txo_sum"] - cs["spent_txo_sum"]) / 1e8
        url = f"https://mempool.space/address/{addr}"
        yield Finding(category="wallet", title="Chain", value="Bitcoin", url=url, confidence=0.99, **base)
        yield Finding(category="wallet", title="Balance", value=f"{bal:.8f} BTC", url=url, confidence=0.99, **base)
        yield Finding(category="wallet", title="Total received", value=f"{cs['funded_txo_sum'] / 1e8:.8f} BTC", url=url,
                      confidence=0.99, **base)
        yield Finding(category="wallet", title="Transactions", value=str(cs["tx_count"]), url=url, confidence=0.99, **base)
        txs = await ctx.get_json(f"https://blockstream.info/api/address/{addr}/txs", headers=API_HEADERS)
        times = [t["status"].get("block_time") for t in txs if t.get("status", {}).get("block_time")]
        if times:
            yield Finding(category="wallet", title="Last activity",
                          value=dt.datetime.fromtimestamp(max(times), dt.timezone.utc).isoformat(), url=url,
                          confidence=0.95, **base)
        yield Finding(category="lead", title="Wallet clustering (WalletExplorer)",
                      value=f"https://www.walletexplorer.com/address/{addr}",
                      url=f"https://www.walletexplorer.com/address/{addr}", confidence=0.5, **base)

    async def _eth(self, addr, ctx, base):
        d = await ctx.get_json(f"https://api.blockcypher.com/v1/eth/main/addrs/{addr}/balance", headers=API_HEADERS)
        url = f"https://etherscan.io/address/{addr}"
        yield Finding(category="wallet", title="Chain", value="Ethereum", url=url, confidence=0.99, **base)
        yield Finding(category="wallet", title="Balance", value=f"{int(d.get('balance', 0)) / 1e18:.6f} ETH", url=url,
                      confidence=0.99, **base)
        yield Finding(category="wallet", title="Total received", value=f"{int(d.get('total_received', 0)) / 1e18:.6f} ETH",
                      url=url, confidence=0.99, **base)
        yield Finding(category="wallet", title="Transactions", value=str(d.get("n_tx", 0)), url=url, confidence=0.99, **base)
