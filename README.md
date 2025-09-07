# wazuh-unifi-decoder
This is a Wazuh decoder xml file for all of the publically documented Ubiquiti Unifi CEF syslog keys. Below is a link to the Ubiquiti documenatation on the syslog CEF key topic.

[https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration)

The decoder uses a parent and sibling decoder structure pattern to allow the decoder to be modular and applicable to any Ubiquiti Unif syslog entery. Below is a link to the Wazuh documentation for the sibling decoder method.
https://documentation.wazuh.com/current/user-manual/ruleset/decoders/sibling-decoders.html
