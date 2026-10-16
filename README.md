# Wazuh decoder for Ubiquiti UniFi (CEF syslog / SIEM integration)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Wazuh 4.14](https://img.shields.io/badge/Wazuh-4.14-3595F9)](https://wazuh.com/)
[![UniFi Network 10.x](https://img.shields.io/badge/UniFi%20Network-10.x-0559C9)](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration)

A **Wazuh** decoder that parses **Ubiquiti UniFi** CEF syslog into searchable fields. It covers every [publicly documented UniFi CEF key](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration), plus keys that real UniFi Network 10.x controllers send but the documentation leaves out (`UNIFIsettings*`, `UNIFIwifi*`, `UNIFInetwork*`, `UNIFIusage*` and others).

Works with any device that runs UniFi Network and exports logs through **Integration → System Logging / SIEM**: UniFi Dream Machine (UDM, UDM Pro, UDM SE), Cloud Gateway (UCG Ultra, UCG Max), Cloud Key, UniFi OS Server, and self-hosted controllers.

📖 **Docs site with install guide, alert table and FAQ: <https://evangress.github.io/wazuh-unifi-decoder/>**

For alerts, install the companion rule set **[wazuh-unifi-rules](https://github.com/evangress/wazuh-unifi-rules)**. It alerts on IDS/IPS threats, admin logins, config and firewall changes, WAN outages and offline devices.

## What gets decoded

- **CEF header:** `event.id`, `event.name`, `event.severity`, `vendor`, `product`, `device.version`
- **UniFi keys** become snake_case fields with a `unifi_` prefix, for example `UNIFIdeviceName` → `unifi_device_name` and `UNIFIwanIsp` → `unifi_wan_isp`. That includes clients, devices, WAN and failover, WiFi and RF, mesh, admin and settings changes, security events, PoE and power, cellular, and certificates.
- **Standard Wazuh fields** are filled too, so built-in rules and dashboards work: `srcip`, `dstip`, `srcport`, `dstport`, `system_name`, `user` and `action`.

Every key has its own sibling decoder, so a key missing from one event never stops the others from being decoded.

## Installation

Tested on Wazuh 4.14.8 with UniFi Network 10.x. Run on the Wazuh **manager**, as root:

```sh
cd /var/ossec/etc
curl -fsSL -o decoders/ubiquiti_decoders.xml \
  https://raw.githubusercontent.com/evangress/wazuh-unifi-decoder/main/ubiquiti_decoders.xml
chown wazuh:wazuh decoders/ubiquiti_decoders.xml
chmod 660 decoders/ubiquiti_decoders.xml
systemctl restart wazuh-manager
```

The default `ossec.conf` loads every file in `etc/decoders`, so no `<ruleset>` change is needed. You can also upload the file in the Wazuh dashboard under **Server management → Decoders** (custom files).

Then add a syslog listener for your UniFi console, point UniFi at Wazuh, and install the rules. The full walkthrough, with a `wazuh-logtest` check and troubleshooting, is in the [wazuh-unifi-rules README](https://github.com/evangress/wazuh-unifi-rules#installation).

### Quick check

Paste this into `/var/ossec/bin/wazuh-logtest`:

```
Oct 10 16:00:00 unifi CEF:0|Ubiquiti|UniFi Network|10.6.106|512|Device Offline|8|UNIFIcategory=UniFi Devices UNIFIdeviceName=Lobby AP UNIFIdeviceModel=U6-Pro UNIFIdeviceIp=192.0.2.20 msg=Lobby AP went offline.
```

Phase 2 should show `name: 'ubiquiti'` with fields such as `unifi_device_name: 'Lobby AP'` and `unifi_device_model: 'U6-Pro'`.

If you used a version of this decoder from before October 2026, upgrade it: older versions don't match syslog-framed CEF (`<timestamp> <host> CEF:0|…`), which is how UniFi sends it.

## Testing

`samples/events.log` holds 41 UniFi events (anonymized live events plus a few marked synthetic), each annotated with the decoder, rule and fields it should produce. `test.py` runs them through `wazuh-logtest` in a Docker lab defined in [`lab/`](lab/README.md), which also loads the rules from [wazuh-unifi-rules](https://github.com/evangress/wazuh-unifi-rules):

```sh
docker compose -f lab/docker-compose.yml up -d
./test.py
docker compose -f lab/docker-compose.yml down -v
```

The lab can also receive live syslog from a UniFi controller; see [`lab/README.md`](lab/README.md).

## Contributing

UniFi's real output differs from its documentation, so new event types and keys keep turning up. If your controller sends a key that isn't decoded, open an issue with an **anonymized** copy of the log line (replace hostnames, client and device names, MAC addresses, IPs and ISP names), or add it to `samples/events.log` and send a pull request.

## How it works

The decoder uses Wazuh's [sibling decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/sibling-decoders.html) pattern: a parent `ubiquiti` decoder matches UniFi CEF lines, and one child decoder per key extracts its value. Because CEF values have no delimiters and can contain spaces, each key uses the same PCRE2 pattern, which captures up to the next `key=` token or the end of the line.

## Credits

Forked from [EvilForge/wazuh-unifi-decoder](https://github.com/EvilForge/wazuh-unifi-decoder) and since extended with syslog-framed CEF support, undocumented UniFi Network 10.x keys, standard Wazuh field mapping, and a test suite.

## License

[MIT](LICENSE)
