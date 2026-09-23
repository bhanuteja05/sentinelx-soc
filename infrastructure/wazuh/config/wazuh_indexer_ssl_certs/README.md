Generated TLS material for the Wazuh single-node stack.

Create certificates (from the repository root):

```bash
docker compose -f infrastructure/wazuh/generate-indexer-certs.yml run --rm generator
```

Do not commit `.pem` or `.key` files. They are gitignored.
