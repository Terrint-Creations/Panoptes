# Contributing to Panoptes

Thanks for wanting to help. Panoptes gets better every time someone teaches it a new trick, fixes a
false positive or finds a source it was missing.

## Ways to help

- **Report a bug.** Open an issue with what you searched for (use a made-up or public example, never a
  private person), what you expected and what happened. Attach `~/.panoptes/logs/panoptes.log` if it
  helps, after removing anything personal.
- **Report a false positive or a dead site.** These are the most valuable bug reports an OSINT tool
  can get.
- **Add a source** (see below) or improve an existing one.
- **Improve the docs or the website.** The site lives in `docs/`.

## Ground rules

1. **Keep it generic.** Every rule, site entry and heuristic must help on any subject. Never tune
   Panoptes to one person, and never commit real people's data, search results, reports, cookies or
   API keys. Use placeholders like `jdoe42` or `Anna Smith` in examples and tests.
2. **Public information only.** No credential stuffing, no exploiting vulnerabilities, no bypassing
   paywalls or access controls, no scraping that a site's login was meant to protect beyond what the
   user's own session allows.
3. **Evidence over guesses.** A finding needs a confidence score that reflects how it was obtained.
   Guesses can be listed, but they must not be followed unless something independent backs them up.
4. **Works on Windows and Linux.** Use `pathlib`, avoid shell-specific commands and guard
   platform-only code with `sys.platform` checks.
5. **Free forever.** Contributions are accepted under the GPL-3.0-or-later, the same license as the
   rest of Panoptes. By opening a pull request you confirm you have the right to submit the code
   under that license.

## Development setup

```bash
git clone https://github.com/<you>/Panoptes && cd Panoptes
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
python -m pip install -e ".[all]"
panoptes update
panoptes search jdoe42 --passive                 # quick smoke test
```

## Adding a source

Subclass `panoptes.sources.base.Source`, set `name`, `kinds` (the entity types it accepts) and
`stage` (`primary`, `enrich` or `late`), and implement `async def search(entity, ctx)` so it yields
`Finding`s. Add pivots to a finding to feed the deep search. Optionally implement
`finalize(ctx, report)` for passes over the whole case. Register it in
`panoptes/sources/__init__.py`.

Use `ctx.get` / `ctx.post` for every request so deadlines, proxies, Tor and per-host limits apply.

## Pull requests

- One topic per pull request, with a short description of what changed and why.
- Run `python -m compileall -q panoptes` and a quick search before you push. CI runs the same checks
  on Windows and Linux.
- Maintainers review every pull request. Some will be accepted, some will be sent back for changes
  and some will be declined if they don't fit the project's direction. A declined pull request is
  never the end of an idea: you are always free to keep it in your own fork.

## Conduct

Be decent to each other. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
