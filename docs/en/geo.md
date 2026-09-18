# geoip / geosite routing

Route by "IP range / domain category", convenient for default behavior like "domestic direct, foreign via proxy". Two data-source formats are supported:

- **`.dat`**: `geoip.dat` / `geosite.dat` (protobuf datasets, one file contains multiple categories).
- **Plain-text list**: one category per file, e.g. domain list `direct-list.txt`, CIDR list `china-cidr.txt`.

## Config: file + category

The top-level `geoip:` / `geosite:` are each a **file list**, each entry a `file` plus the `cats` (category name list) to load. Files are distinguished by extension:

- **`.dat`**: one file, multiple categories; `cats` lists the categories to use; **empty `cats` = load all categories in that file**. The whole file is parsed only once; multiple categories are not read repeatedly.
- **Text list** (non-`.dat`): the whole file is one category; `cats` must give **exactly one category name**.

The `geo` section only handles "**which data to load**"; what to do on a match (`target`/`dns`/`proxy`) is still written in `hosts`, and the **positioning** of the `geoip:xx` / `geosite:xx` rules in `hosts` decides priority (ordering flexibility is unaffected).

```yaml
geoip:
  - file: ./geoip.dat         # One .dat fetches multiple categories at once, parsed only once
    cats: [cn, us]            # Categories to use; empty loads all categories in that .dat
  - file: ./cloudflare.txt    # Text CIDR list, the whole file is one category
    cats: [cloudflare]        # Text list must give exactly one category name
geosite:
  - file: ./geosite.dat
    cats: [google, cn]

default:
  target: remote              # Default via proxy
hosts:
  - name: geoip:cn            # Target IP hits geoip category cn → direct
    target: local
  - name: geosite:cn          # Target domain hits geosite category cn → direct
    target: local
```

Effect: domestic IP / domestic domain direct, the rest via proxy. What follows `geoip:`/`geosite:` is the **category name** (case-insensitive), i.e. the category you loaded in the `geoip:`/`geosite:` `cats`.

### Same category can merge from multiple files (union)

**The same category can be merged from multiple files** (`.dat` + text both work, accumulating across entries); merging is a **union**: duplicates are auto-deduped, and `geoip:cn` / `geosite:cn` in `hosts` matches the **sum of all loaded files for that category**. Suitable for stacking "`.dat` built-in category + your own maintained supplementary list":

```yaml
geosite:
  - file: ./geosite.dat        # Category cn takes the .dat built-in cn rules
    cats: [cn]
  - file: ./direct-list.txt    # Category cn then stacks the text list (one domain per line)
    cats: [cn]
# geosite:cn in hosts matches both files above (union)
```

Loading runs **in order** per the `geoip:`/`geosite:` list, merging the same category repeatedly; category names are case-insensitive (`cn` and `CN` map to the same category). If an entry fails to load (e.g. `.dat` has no such category, text list parses no domains) it only logs a hint, does **not abort startup**, and that entry's content is ineffective.

### Text list format

- **geoip text**: one `CIDR` per line (e.g. `1.2.0.0/16`) or bare IP; `#` comment; attributes after in-line spaces are ignored.
- **geosite text** (domain list): one domain per line, with prefix:
  - no prefix or `domain:` → **suffix** (root domain and all subdomains)
  - `full:` → exact
  - `keyword:` / `regexp:` → **discarded** (treated as foreign domain)
  - `#` comment; the `domain @attr` attribute part is ignored.

### `.dat` offline extraction of small file (optional)

The full `.dat` contains all categories and is large. You can use the built-in command to **extract offline** the needed categories into a small `.dat` to ship with releases (at runtime only the small file is read):

```bash
anyproxy -geo-extract -geo-in geosite.dat -geo-cat cn,google -geo-out geosite-cn.dat
```

`-geo-cat` comma-separated can extract multiple at once; geoip.dat/geosite.dat outer format is identical, the same command works for both; it exits after extraction. Obtain the full `geoip.dat` / `geosite.dat` yourself. After swapping in a new full `.dat` you must **re-extract** (the program does no caching/auto-update, to avoid stale data).

## Matching semantics

- **geoip:xx**: the target IP falls within any CIDR of that category → match. Internally sorted CIDR + binary search, O(log n). v4/v6 both supported.
- **geosite:xx**: only two domain types are used (`.dat` Domain/Full, text's no-prefix·domain/full) —
  - **Domain (suffix)**: e.g. `baidu.com` matches `baidu.com` and **all its subdomains** `www.baidu.com`, `a.b.baidu.com`.
  - **Full (exact)**: matches only the complete domain itself.
  - **keyword (substring) / regex (regexp) are discarded and treated as foreign domains** (these two are rare and high-uncertainty).

## Notes

- `geo` data is loaded **once at startup**, not hot-reloaded with config (swap `.dat` → restart). The `geoip:`/`geosite:` rules in `hosts` themselves can be hot-reloaded, but depend on data already loaded at startup.
- Using a `geoip:`/`geosite:` rule but not loading the corresponding category in the top-level `geoip:`/`geosite:` (or old `geo.ip`/`geo.site`) means the rule **never matches** (a hint is printed), and traffic falls to `default`.
- geoip matches the **target IP**: transparent proxy/TUN naturally has the target IP; a normal proxy request also has the resolved IP. geosite matches the **domain**: transparent proxy/TUN relies on first-packet sniffing of TLS SNI / HTTP Host to recover it (see [routing.md](routing.md), [usage.md](usage.md)); if it can't be sniffed, only geoip can be used.
- Zero third-party dependency: a built-in minimal protobuf parser reads `.dat`, without pulling in a protobuf library or depending on any third-party rule-library code (`utils/geo/`). Text lists are parsed in the same package.

## Relationship with other rules

`geoip:`/`geosite:` is just a value of `hosts[].name`, matched in `hosts` **order** like ordinary domain rules and the `*` wildcard; the first match uses its `target`/`proxy`/`dns` etc. Earlier wins. Egress decision see [proxy-decision.md](proxy-decision.md).
