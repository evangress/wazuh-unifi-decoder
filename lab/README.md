# Wazuh lab

A throwaway Wazuh manager in Docker that loads this repo's decoder and the rules from
[wazuh-unifi-rules](https://github.com/evangress/wazuh-unifi-rules). Use it to run
`test.py` or to receive live syslog from a UniFi controller. Not for production.

## Start

Clone both repos side by side, then from this repo's root:

```sh
docker compose -f lab/docker-compose.yml up -d
docker exec wazuh-lab /var/ossec/bin/wazuh-control status   # wait until wazuh-analysisd is running
./test.py
```

If the rules repo is somewhere else, set `UNIFI_RULES_REPO=/path/to/wazuh-unifi-rules`.

After editing a decoder or rule, `./test.py` restarts Wazuh for you. To reload by hand, run
`docker exec wazuh-lab /var/ossec/bin/wazuh-control restart`.

## Live logs from a UniFi controller

1. In UniFi Network, go to **Integration → System Logging / SIEM**, choose **SIEM Server**,
   and enter the IP address of the machine running Docker, port **514**.
2. Check whether events arrive:
   ```sh
   docker exec wazuh-lab tail -f /var/ossec/logs/archives/archives.log | grep '|Ubiquiti|'
   ```
   Decoded fields and matched rules are in `logs/archives/archives.json`; alerts
   (level 3 and above) are in `logs/alerts/alerts.json`.
3. If nothing arrives, check the host firewall. macOS's application firewall, especially
   in stealth mode, can drop incoming UDP for Docker. Allow Docker under
   **System Settings → Network → Firewall → Options**. To check whether packets reach the
   host at all, run `sudo tcpdump -ni <interface> udp port 514`.

On Docker Desktop, events show the Docker gateway as their source (for example
`192.168.65.1`), not the controller's IP. That's why `ossec.conf` allows syslog from any
address.

Turning on **debug** logging in the controller's syslog settings makes devices send verbose
non-CEF syslog, including device auth keys. Leave it off.

## Stop and delete

```sh
docker compose -f lab/docker-compose.yml down -v
```

The container keeps nothing worth saving; recreate it any time with `up -d`.
