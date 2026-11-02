# 镜 Jing (Mirror)

**De-anonymize yourself before someone else does.**

You keep identities apart on purpose: a real name, a business, a handle, an alias. 镜 takes the
public evidence an investigator would use and tries to link them back together. Every link that
crosses a separation you declared is reported with the field it rests on, its source, and a
severity.

Python 3 standard library only. No API keys. One file.

## What it checks

| Source | What it looks for |
|---|---|
| GitHub (public API) | Commit author/committer names and emails in every public repo you own, profile fields, commit timezone offsets |
| RDAP / whois | Registrant data that isn't redacted (note: `.us` forbids WHOIS privacy entirely) |
| DNS (`dig`, DoH fallback) | Two domains sharing a Cloudflare nameserver pair (same account), shared TXT verification tokens, SOA/MX contacts |
| Certificate Transparency (crt.sh) | A single certificate naming domains from two separated identities |
| Your web pages | Shared analytics / Cloudflare beacon IDs, emails, author tags, HTML comments, your private strings |

Anything it can't check automatically (Discord, forum accounts) becomes a checklist in the report.

## Quick start

```
cp mirror.example.json mirror.json && chmod 600 mirror.json
cp assets.example.md assets.md
```

1. In `assets.md`, list only domains and GitHub accounts **you own**.
2. In `mirror.json`, declare your identities (`clusters`), which domain/account belongs to which,
   and your `private_identifiers`: real name, personal emails, town.
3. Run:

```
python3 mirror.py --config mirror.json --registry assets.md --out linkage.md; echo "exit=$?"
```

Exit codes: `0` no cross-separation links · `1` links found · `2` a reading failed or scope
unconfirmed. **A failed reading is never treated as clean** — it's listed loudly and forces exit 2.

## How to read it

- **Clusters** are groups of identities that are *allowed* to be linked. A link inside a cluster
  is listed for reference. A link between clusters is a finding.
- `private_identifiers` never appear in the report — matches show only by label
  (`matched private identifier: real name`), so the report is safe to share for help.
- Keep `mirror.json` at mode 600 and out of git. It is a short dossier on you.

## Scope and ethics

镜 audits **you**. The asset list is a scope gate: any domain or account in the config that isn't
in your asset list aborts the run with `SCOPE UNCONFIRMED`. That's a guard rail against mistakes,
not enforcement — so be clear about the rule: pointing this at someone else's accounts to unmask
them is doxxing, and it's not what this is for.

## FAQ

**Does it work on Discord?** Not automatically. Discord has no public API for profile lookups,
and automating a user account (a "self-bot") breaks Discord's Terms of Service. 镜 adds Discord
items to the manual checklist instead. A planned module will read *your own* Discord data export
(Settings → Data & Privacy → Request your data) offline, so you can audit your own connections
without touching the API.

**Why did DNS fail on my server?** If you run a filtering resolver (NextDNS, Pi-hole) that blocks
DNS-over-HTTPS, the DoH fallback fails. Install `dig` (`dnsutils`), or set
`MIRROR_DNS=@1.1.1.1` to query a named resolver.

**I fixed a leaked commit email — is it gone?** New commits: set GitHub → Settings → Emails →
*Keep my email addresses private* and *Block command line pushes that expose my email*. Old
commits: rewrite the author email and force-push. Clones and archives made before that keep the
old copies; rewriting stops the link going forward, it can't recall copies.

## License

MIT
