# Proof of Concept

## Development

```bash
./scripts/start --port 3001 --host did-auth1.test
./scripts/start --port 3002 --host did-auth2.test
```

### Using a local HTTPS proxy like puma.dev

```bash
DEBUG=did-web-auth*,knex:query,knex:tx DATABASE_FILE=./tmp/did-auth2.sqlite ./scripts/dev-start --port 7210 --host did-auth2.test
```

```env
SESSION_SECRET=

```

## Testing

Running the test suite requires a DNS and HTTPs proxy like puma.dev

