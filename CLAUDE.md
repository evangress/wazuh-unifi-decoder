# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A single Wazuh decoder file, `ubiquiti_decoders.xml`, that parses UniFi CEF syslog messages. It covers the publicly documented UniFi CEF keys listed at https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration. It is a fork of EvilForge/wazuh-unifi-decoder and is MIT-licensed. The license text is also in the XML header comment, so keep that header intact.

There is no build, lint, or test tooling in the repo. To validate changes, you need a Wazuh manager: copy the file into `/var/ossec/etc/decoders/`, restart the manager, and paste sample UniFi CEF lines into `/var/ossec/bin/wazuh-logtest`.

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

- **The parent decoder needs a `<program_name>`.** UniFi syslog arrives as `Oct 10 16:00:00 UDM-Pro CEF:0|Ubiquiti|…`. Wazuh's pre-decoder treats `CEF` as the program name and strips `CEF:` from the message. When a log has a program name, Wazuh only tries decoders that declare `<program_name>`. A parent with only `<prematch>` therefore never matches real syslog, even though it works on a bare `CEF:0|…` line. Use `<program_name type="pcre2">.*</program_name>`, and write the prematch and header regexes so they don't require the `CEF:` prefix.
- **Never put `<!` inside a regex,** for example a negative lookbehind `(?<!…)`. Wazuh's XML parser reads it as the start of a comment, and analysisd refuses to start. Use `\b` instead.

- **Live UniFi output differs from the docs.** UniFi Network 10.x uses categories such as `Audit` and `Client Devices`, not only the documented `Monitoring`/`System`. It also sends keys that the documented list leaves out (`UNIFIsettings*`, `UNIFIutcTime`, `UNIFIwifi*`, `UNIFInetwork*`, `UNIFIusage*`, `UNIFIduration`). Treat real logs as the source of truth.

## Companion rules repo

Alert rules live in `../wazuh-unifi-rules/ubiquiti_rules.xml`, with rule IDs 100010–100399. Every rule hangs off base rule `100010` (`<decoded_as>ubiquiti</decoded_as>`), so decoder field names (`event.name`, `unifi_category`, `unifi_sub-category`, …) are effectively an API for that repo. Renaming a field breaks rules there. Wazuh tries sibling rules from highest level to lowest, not in file order. A rule that should *lower* the level of a broader match must be that rule's child.

## Lab testing in Docker

Mount both repos as **directories**. A single-file bind mount silently breaks when an editor or `sed -i` replaces the file instead of writing in place, and the file then disappears inside the container.

```sh
docker run -d --name wazuh-lab -h wazuh-lab -p 514:514/udp \
  -v <lab>/ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro \
  -v "$PWD":/var/ossec/etc/unifi-decoder:ro \
  -v "$PWD/../wazuh-unifi-rules":/var/ossec/etc/unifi-rules:ro \
  wazuh/wazuh-manager:4.14.8
docker exec wazuh-lab /var/ossec/bin/wazuh-control restart        # after any decoder/rule edit
docker exec -i wazuh-lab /var/ossec/bin/wazuh-logtest < samples.log  # decoder + rule results per line
```

The lab `ossec.conf` differs from the default in these ways:
- `<decoder_dir pattern=".xml$">etc/unifi-decoder</decoder_dir>` and `<rule_dir pattern=".xml$">etc/unifi-rules</rule_dir>` inside `<ruleset>`.
- A `<remote><connection>syslog</connection><port>514</port><protocol>udp</protocol><allowed-ips>0.0.0.0/0</allowed-ips></remote>` block.
- `<logall_json>yes</logall_json>`, so events that match no rule still land in `logs/archives/archives.json`.

On Docker Desktop, incoming UDP shows the Docker gateway as its source (for example `192.168.65.1`), not the controller's IP. After an edit, check `grep analysisd /var/ossec/logs/ossec.log` for XML errors and duplicate rule IDs.
