# Elastic Security to AstoraSOC

Use this integration with Elastic Security detection rules and Kibana connectors.

## Files

- `astorasoc_elastic.py` - optional bridge script for exported alert JSON.

## Recommended Method: Webhook Connector

1. In Kibana, create a connector of type Webhook.
2. Set URL:

   ```text
   https://astorasoc.example.com/api/webhook/alert
   ```

3. Add headers:

   ```text
   X-API-Key: <AstoraSOC key>
   Content-Type: application/json
   ```

4. Configure the rule action body using Elastic alert fields such as `kibana.alert.rule.name`, `kibana.alert.severity`, `host.name`, `source.ip`, and `user.name`.
5. Include the full alert object as `raw_alert`.
6. Test the connector and confirm the alert appears in AstoraSOC.

## Bridge Script Option

```bash
python3 astorasoc_elastic.py elastic-alert.json "$ASTORASOC_API_KEY" "$ASTORASOC_WEBHOOK_URL"
```

## Field Mapping

Common Elastic fields: `@timestamp`, `kibana.alert.uuid`, `kibana.alert.rule.name`, `kibana.alert.severity`, `host.name`, `user.name`, `source.ip`, `destination.ip`, `threat.*`.
