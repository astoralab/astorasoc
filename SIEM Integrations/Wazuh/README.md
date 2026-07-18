# Wazuh to AstoraSOC

Use this integration when Wazuh `integratord` should forward alerts into AstoraSOC.

## Files

- `custom-astorasoc.py` - Wazuh custom integration script.

## Steps

1. Copy `custom-astorasoc.py` to the Wazuh manager integration directory:

   ```bash
   sudo cp custom-astorasoc.py /var/ossec/integrations/custom-astorasoc
   sudo chmod 750 /var/ossec/integrations/custom-astorasoc
   sudo chown root:wazuh /var/ossec/integrations/custom-astorasoc
   ```

2. Generate the AstoraSOC webhook API key in Admin Settings.

3. Add the integration block to `/var/ossec/etc/ossec.conf`:

   ```xml
   <integration>
     <name>custom-astorasoc</name>
     <hook_url>https://astorasoc.example.com/api/webhook/alert</hook_url>
     <api_key>replace-with-astorasoc-api-key</api_key>
     <level>7</level>
     <alert_format>json</alert_format>
   </integration>
   ```

4. Restart Wazuh manager:

   ```bash
   sudo systemctl restart wazuh-manager
   ```

5. Watch the integration log:

   ```bash
   sudo tail -f /var/ossec/logs/integrations.log
   ```

## Test

```bash
/var/ossec/integrations/custom-astorasoc /tmp/sample-alert.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL" --dry-run
```

The script safely ignores extra Wazuh internal arguments such as retry counters or shell redirection fragments.
