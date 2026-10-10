# wazuh-unifi-decoder
This is a Wazuh decoder xml file for all of the publically documented Ubiquiti Unifi CEF syslog keys. Below is a link to the Ubiquiti documenatation on the syslog CEF key topic.

[https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration)

The decoder uses a parent and sibling decoder structure pattern to allow the decoder to be modular and applicable to any Ubiquiti Unif syslog entery. Below is a link to the Wazuh documentation for the sibling decoder method.
https://documentation.wazuh.com/current/user-manual/ruleset/decoders/sibling-decoders.html

## Testing

`samples/events.log` holds anonymized UniFi events, each annotated with the decoder, rule and fields it should produce. `test.py` runs them through `wazuh-logtest` in a Docker lab defined in [`lab/`](lab/README.md), which also loads the rules from [wazuh-unifi-rules](https://github.com/evangress/wazuh-unifi-rules):

```sh
docker compose -f lab/docker-compose.yml up -d
./test.py
docker compose -f lab/docker-compose.yml down -v
```
