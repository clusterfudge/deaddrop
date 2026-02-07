# Deploying Deaddrop to Dokku

This guide covers deploying deaddrop to a Dokku server with SSL.

## Prerequisites

- Dokku server with `letsencrypt` plugin installed
- SSH access to the Dokku server
- Git repository with deaddrop code

## Initial Setup

### 1. Create the Dokku App

```bash
# Create the app on the Dokku server
ssh dokku@dokku.heare.io apps:create deaddrop

# Or for a test instance
ssh dokku@dokku.heare.io apps:create deaddrop-test
```

### 2. Configure Environment

```bash
# For development/testing (no auth required)
ssh dokku@dokku.heare.io config:set deaddrop-test DEADROP_NO_AUTH=1

# For production with heare-auth
ssh dokku@dokku.heare.io config:set deaddrop HEARE_AUTH_URL=https://auth.heare.io

# For production with Turso database
ssh dokku@dokku.heare.io config:set deaddrop TURSO_URL=libsql://your-db.turso.io
ssh dokku@dokku.heare.io config:set deaddrop TURSO_AUTH_TOKEN=your-token
```

### 3. Add Git Remote

```bash
# For main production app
git remote add dokku dokku@dokku.heare.io:deaddrop

# For test app
git remote add dokku-test dokku@dokku.heare.io:deaddrop-test
```

### 4. Deploy

```bash
# Deploy main branch to production
git push dokku main

# Deploy feature branch to test
git push dokku-test feature/my-feature:main
```

### 5. Set Up SSL with Let's Encrypt

```bash
# Set email for Let's Encrypt (required)
ssh dokku@dokku.heare.io letsencrypt:set deaddrop-test email your-email@example.com

# Enable Let's Encrypt
ssh dokku@dokku.heare.io letsencrypt:enable deaddrop-test
```

## Testing the Deployment

### Health Check

```bash
curl https://deaddrop-test.dokku.heare.io/health
# Expected: {"status":"ok"}
```

### Create Test Namespace

```bash
# Create namespace (no auth required in test mode)
curl -X POST https://deaddrop-test.dokku.heare.io/admin/namespaces \
  -H "Content-Type: application/json" \
  -d '{"metadata": {"display_name": "Test"}, "slug": "test"}'
```

### Create Identities

```bash
NS="<namespace_id>"
NS_SECRET="<namespace_secret>"

# Create Alice
curl -X POST "https://deaddrop-test.dokku.heare.io/$NS/identities" \
  -H "Content-Type: application/json" \
  -H "X-Namespace-Secret: $NS_SECRET" \
  -d '{"metadata": {"display_name": "Alice"}}'

# Create Bob
curl -X POST "https://deaddrop-test.dokku.heare.io/$NS/identities" \
  -H "Content-Type: application/json" \
  -H "X-Namespace-Secret: $NS_SECRET" \
  -d '{"metadata": {"display_name": "Bob"}}'
```

### Test E2E Encryption

Use the CLI to test encryption:

```bash
# Update CLI config to point to test server
sed -i '' 's|deaddrop.dokku.heare.io|deaddrop-test.dokku.heare.io|' ~/.config/deadrop/config.yaml

# Generate keys for both identities
deadrop identity generate-keys <ns> <alice_id>
deadrop identity generate-keys <ns> <bob_id>

# Send encrypted message
deadrop message send <ns> <bob_id> "Secret message" --identity-id <alice_id>

# Read inbox (auto-decrypts)
deadrop message inbox <ns> <bob_id>
```

## Useful Commands

### View Logs

```bash
ssh dokku@dokku.heare.io logs deaddrop-test -t
```

### Restart App

```bash
ssh dokku@dokku.heare.io ps:restart deaddrop-test
```

### Check App Status

```bash
ssh dokku@dokku.heare.io ps:report deaddrop-test
```

### Destroy Test App

```bash
ssh dokku@dokku.heare.io apps:destroy deaddrop-test --force
```

## Troubleshooting

### SSL Issues

If Let's Encrypt fails:

```bash
# Check nginx config
ssh dokku@dokku.heare.io nginx:show-config deaddrop-test

# Rebuild nginx config
ssh dokku@dokku.heare.io nginx:build-config deaddrop-test
```

### Database Issues

For SQLite (default), the database is stored in `/app/deadrop.db` inside the container.
Note: Container restarts will lose the database. Use Turso for persistence.

### Build Failures

Check the Python version matches `runtime.txt`:

```bash
cat runtime.txt
# Should be: python-3.11.9 or similar
```
