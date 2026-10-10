# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A single Wazuh decoder file, `ubiquiti_decoders.xml`, that parses UniFi CEF syslog messages. It covers the publicly documented UniFi CEF keys listed at https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration. It is a fork of EvilForge/wazuh-unifi-decoder and is MIT-licensed. The license text is also in the XML header comment, so keep that header intact.

## Testing

```sh
./test.py              # restart Wazuh in the lab container, run every sample, check expectations
./test.py -v           # also list passing samples
./test.py --no-reload  # skip the ~10 s restart when nothing changed
```

`test.py` needs the Docker lab described below. It feeds `samples/events.log` through `wazuh-logtest` and checks each line against the `# expect:` comment above it: decoder, rule ID, level, and required non-empty fields. It also fails if a sample contains a CEF key that has no decoder. When a new UniFi event type shows up, anonymize it (hostnames, client names, MACs, IPs), add it to `samples/events.log` with an expectation, and run the tests. Samples marked "synthetic" stand in for events not yet seen from a real controller.

Note: `.gitignore` contains `*/`, which ignores **every subdirectory**. If you add folders such as `rules/` or sample logs, git will skip them until you change `.gitignore`.

## Decoder architecture

The file uses Wazuh's [sibling decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/sibling-decoders.html) pattern:

- One parent `<decoder name="ubiquiti">` matches on `<prematch>Ubiquiti</prematch>`.
- Every other decoder is also named `ubiquiti`, has `<parent>ubiquiti</parent>`, and extracts exactly **one** key. Because siblings are independent, a key that is missing from a message doesn't stop the other keys from being decoded.
- The first child parses the CEF header (`CEF:ver|Ubiquiti|UniFi …|version|event id|name|severity`) into `cef.tag`, `cef.version`, `vendor`, `product`, `device.version`, `event.id`, `event.name`, and `event.severity`.

The CEF extension values have no delimiters and can contain spaces, so every key decoder uses the same PCRE2 shape:

```xml
<regex type="pcre2">KEYNAME=([^\s].*?)\s*(?=[A-Za-z0-9_.:-]+=|$)</regex>
```

This means "capture lazily until the next `key=` token or the end of the line." Copy this pattern for any new key.

### Conventions

- **Field naming:** `UNIFIfooBarBaz` keys become snake_case outputs prefixed with `unifi_`, for example `UNIFIconnectedToDeviceIp` → `unifi_connected_to_device_ip`. Standard CEF keys (`msg`, `src`, `reason`, `cnt`, `deviceOutboundInterface`) keep their short names. `suser` becomes `user`.
- **Mapping to Wazuh standard fields:** some keys are decoded **twice on purpose**, with the same regex and a different `<order>`, so the value also fills a standard Wazuh field that rules and dashboards rely on:
  - `UNIFIclientIp` → `srcip`
  - `UNIFIclientHostname` → `system_name`
  - `UNIFIconnectedToDeviceIp` → `dstip`
  - `UNIFIconnectedToDevicePort` → `dstport`
  - `UNIFIdevicePort` → `srcport`
  - `msg` → `action`

  These duplicates are intentional, so don't merge or remove them as redundant.
- Decoders are kept roughly alphabetical by key name after the header and core CEF fields.

### Wazuh pitfalls (verified with wazuh-logtest on 4.14.8)

- **There are two parent decoders, and both are needed.** UniFi syslog arrives as `Oct 10 16:00:00 UDM-Pro CEF:0|Ubiquiti|…`. Wazuh's pre-decoder treats `CEF` as the program name and strips `CEF:` from the message. When a log has a program name, Wazuh only tries decoders that declare `<program_name>`; when it has none, it only tries decoders that don't. The first parent therefore uses `<program_name type="pcre2">.*</program_name>` with a prematch that doesn't require `CEF:`. The second parent has no `<program_name>` and covers bare `CEF:0|…` lines. Both are named `ubiquiti`, so every sibling decoder attaches to both. Keep the header regex free of the `CEF:` prefix.
- **Never put `<!` inside a regex,** for example a negative lookbehind `(?<!…)`. Wazuh's XML parser reads it as the start of a comment, and analysisd refuses to start. Use `\b` instead.

- **Live UniFi output differs from the docs.** UniFi Network 10.x uses categories such as `Audit` and `Client Devices`, not only the documented `Monitoring`/`System`. It also sends keys that the documented list leaves out (`UNIFIsettings*`, `UNIFIutcTime`, `UNIFIwifi*`, `UNIFInetwork*`, `UNIFIusage*`, `UNIFIduration`). Treat real logs as the source of truth.

## Companion rules repo

Alert rules live in `../wazuh-unifi-rules/ubiquiti_rules.xml`, with rule IDs 100010–100399. Every rule hangs off base rule `100010` (`<decoded_as>ubiquiti</decoded_as>`), so decoder field names (`event.name`, `unifi_category`, `unifi_sub-category`, …) are effectively an API for that repo. Renaming a field breaks rules there. Wazuh tries sibling rules from highest level to lowest, not in file order; on a tie, the earlier rule in the file wins. A rule that should *lower* the level of a broader match must be that rule's child. The CEF-severity fallbacks (100390–100392) are siblings of the specific rules. UniFi sends a fixed severity per event type, so give each specific rule a level at least equal to its severity's fallback level, and keep it above the fallbacks in the file. Otherwise the generic fallback wins.

## Lab testing in Docker

The lab is defined in `lab/`: `docker-compose.yml`, a lab-only `ossec.conf`, and `README.md`, which covers pointing a live controller at it and firewall troubleshooting. It expects `wazuh-unifi-rules` cloned next to this repo; override that with `UNIFI_RULES_REPO`.

```sh
docker compose -f lab/docker-compose.yml up -d     # container "wazuh-lab", syslog on 514/udp
./test.py                                         # restarts Wazuh, runs samples/events.log
docker compose -f lab/docker-compose.yml down -v   # delete it; nothing in it needs keeping
```

- The compose file mounts both repos as **directories** on purpose. A single-file bind mount silently breaks when an editor or `sed -i` replaces the file instead of writing in place, and the file then disappears inside the container.
- `lab/ossec.conf` is the image's default config plus changes marked `LAB`: full archiving (`logall_json`), a syslog listener on 514/udp open to any IP, and `decoder_dir`/`rule_dir` entries for the mounted repos. Regenerate it from the image if you upgrade Wazuh.
- On Docker Desktop, incoming UDP shows the Docker gateway as its source (for example `192.168.65.1`), not the controller's IP.
- After an edit, check `docker exec wazuh-lab grep analysisd /var/ossec/logs/ossec.log` for XML errors and duplicate rule IDs. `test.py` reports new ones automatically.
