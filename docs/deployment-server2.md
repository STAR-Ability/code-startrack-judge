# Manual server2 deployment — UNQUALIFIED PR #25 image

PR [#25](https://github.com/STAR-Ability/code-startrack-judge/pull/25) merged without a protection bypass on 2026-10-10. The source commit is `b8eb47e74540ae36439636f8d2ae776f001033da`; its tree is the previously verified PR head's tree. This image is **UNQUALIFIED / PRE_RELEASE / NOT_DEPLOYED**. Publication is authorized separately from production qualification. No production release, production pointer, `latest` tag, or automatic deployment is created.

| Artifact | Reference |
| --- | --- |
| Linux amd64 service tag | `ghcr.io/star-ability/code-startrack-judge:unqualified-pr25-git-b8eb47e74540ae36439636f8d2ae776f001033da` |
| Service manifest digest | `sha256:b883f4749d4ce8890d313b923017c21c9baf029bc76fc2f1e204b25491f52ea5` |
| Corresponding-source tag | `ghcr.io/star-ability/code-startrack-judge-sources:unqualified-pr25-git-b8eb47e74540ae36439636f8d2ae776f001033da` |
| Corresponding-source manifest digest | `sha256:2703e004ffd932bd1e7e5d2865b55c659b704276cebc5a07550853e9d1db25a4` |
| Publication and recipe evidence | [Successful build-only Actions run](https://github.com/STAR-Ability/code-startrack-judge/actions/runs/38015743267) |
| Contract / API / shipped migrations | `0.2.0` / `/internal/v2` / `1`–`5` |

The build-only recipe omits the original Dockerfile's Go unit tests, problemtools wheel audit, and pip dependency check at the user's request. Release-oriented Go dependency/legal inventory audit preparation is also omitted after it rejected the fresh-runner source closure; that gate remains unresolved. The pinned compilation inputs, upstream patches, actual legal texts, original recipe, and actual recipe override are retained in the corresponding-source artifact. The image's `/opt/startrack/provenance/unqualified-build.json` records the omissions. No further image audit, Linux qualification, Backend acceptance, or deployment test is claimed. Build input checksum/signature handling is retained for reproducible source preparation.

The merge-triggered additional Foundation run was canceled; the existing PR checks had already passed before merge. The normal protected-main artifact workflow consequently skipped. The publication workflow lives on the dedicated `artifact/unqualified-pr25-b8eb47e` branch and checks out the exact merged source; it changes no `main` protection or canonical validation workflow.

These instructions describe a **manual, bounded candidate installation** on the existing shared server. The earlier server2 startup/restart run did not pass, and the last recorded Backend `/health` returned 503; see the [retained report](releases/v0.2-shared-server-2026-10-09.md). No current server health is asserted here. The 3 GiB / one CPU outer Judge limit below follows that bounded candidate scope; it does not establish full package or concurrency capacity. The [production runbook](deployment/production.md) describes the larger proposed profile and remaining qualification requirements. A successful `/health` response does not promote this image to production qualification.

## 1. Open the operator session and prepare directories

All following commands are instructions for the operator. They have not been executed against server2 as part of this publication. Use an amd64 Linux host with Docker Engine, Compose v2, cgroup v2, AppArmor, and the candidate namespace/seccomp support described in the production runbook. The operator commands require Git, Python 3, OpenSSL, curl, awk, tar, and `apparmor_parser` on the host. Keep Backend admission to this candidate disabled throughout initial setup.

```sh
# Run locally; then continue in the server's root shell.
ssh server2
sudo -i
bash
set -euo pipefail
umask 077

install -d -m 0700 /opt/startrack-judge-pr25
cd /opt/startrack-judge-pr25
install -d -m 0700 secrets db-secrets config tls tls/authority tls/postgres backups
install -d -m 0755 data data/startrack data/startrack-judger
install -d -m 0700 data/supervisor

# Fresh pinned checkout for SQL and deployment references; no existing app checkout is modified.
git clone --no-checkout https://github.com/STAR-Ability/code-startrack-judge.git source
git -C source checkout --detach b8eb47e74540ae36439636f8d2ae776f001033da
```

For an existing installation, use the backup and stop procedure in section 7 before changing files. Do not regenerate its credentials or initialize its database. This recipe uses a separate Judge-owned database and private network and does not access Backend tables. PostgreSQL is infrastructure, not an additional platform business service.

If the GHCR packages are private, authenticate as an account with access to **both** source and binary packages. Enter a token with `read:packages` interactively; keep shell tracing disabled.

```sh
read -r -p 'GitHub login: ' GHCR_USER
read -r -s -p 'GHCR read token: ' GHCR_TOKEN
printf '\n'
printf '%s' "$GHCR_TOKEN" | docker login ghcr.io --username "$GHCR_USER" --password-stdin
unset GHCR_TOKEN

JUDGE_IMAGE='ghcr.io/star-ability/code-startrack-judge@sha256:b883f4749d4ce8890d313b923017c21c9baf029bc76fc2f1e204b25491f52ea5'
JUDGE_IMAGE_DIGEST='sha256:b883f4749d4ce8890d313b923017c21c9baf029bc76fc2f1e204b25491f52ea5'
POSTGRES_IMAGE='postgres:17.10-bookworm@sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f'
docker pull "$JUDGE_IMAGE"
docker pull "$POSTGRES_IMAGE"
```

Use the manifest digest above, not a Docker image/configuration ID or a mutable tag. The corresponding-source carrier is data only and must never be started. Preserve its immutable digest and access alongside the binary; Actions attachments expire after 90 days and need a durable operator archive.

Extract the image's configuration and executable checksum record from a container that is created but **never started**:

```sh
JUDGE_EXTRACT_CONTAINER=$(docker create --entrypoint /bin/true "$JUDGE_IMAGE")
docker cp "$JUDGE_EXTRACT_CONTAINER:/opt/startrack/startrack-v02.apparmor" config/
docker cp "$JUDGE_EXTRACT_CONTAINER:/opt/startrack/startrack-v02.seccomp.json" config/
docker cp "$JUDGE_EXTRACT_CONTAINER:/opt/startrack/provenance/binaries.sha256" config/
docker cp "$JUDGE_EXTRACT_CONTAINER:/opt/startrack/provenance/unqualified-build.json" config/
docker rm "$JUDGE_EXTRACT_CONTAINER"
unset JUDGE_EXTRACT_CONTAINER
chmod 0600 config/*

# Load the supplied candidate profile; do not replace it with an unconfined profile.
apparmor_parser --replace config/startrack-v02.apparmor
```

## 2. Configure the dedicated TLS database and credentials

This section initializes a **fresh** dedicated `judge` database. For an existing Judge database, retain its data and TLS authority and use its approved Judge-only operator/migration/runtime credentials instead. Do not apply this database's ACL baseline to a shared Backend database.

Generate a private TLS authority and a server certificate whose DNS identity matches the Compose service name `postgres`. The authority key is outside the mounted PostgreSQL directory.

```sh
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -subj '/CN=startrack-pr25-db-ca' \
  -keyout tls/authority/ca.key -out tls/ca.crt
openssl req -new -newkey rsa:3072 -nodes \
  -subj '/CN=postgres' -keyout tls/postgres/server.key -out tls/postgres/server.csr
cat > tls/postgres/server.ext <<'EOF'
subjectAltName=DNS:postgres
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF
openssl x509 -req -sha256 -days 365 -in tls/postgres/server.csr \
  -CA tls/ca.crt -CAkey tls/authority/ca.key -CAcreateserial \
  -extfile tls/postgres/server.ext -out tls/postgres/server.crt

# Discover the pinned database image's identity instead of assuming the host's postgres UID.
PG_UID=$(docker run --rm --entrypoint id "$POSTGRES_IMAGE" -u postgres)
PG_GID=$(docker run --rm --entrypoint id "$POSTGRES_IMAGE" -g postgres)
chown "$PG_UID:$PG_GID" tls/postgres/server.key tls/postgres/server.crt
chmod 0400 tls/postgres/server.key
chmod 0444 tls/postgres/server.crt tls/ca.crt
chmod 0755 tls/postgres
rm tls/postgres/server.csr tls/postgres/server.ext

cat > config/pg_hba.conf <<'EOF'
local   all     postgres                              peer
local   all     all                                   reject
hostssl judge   judge_migration,judge_runtime  all     scram-sha-256
host    all     all                           all     reject
EOF
chmod 0444 config/pg_hba.conf
```

Create independent file credentials. The two directional S2S tokens must match the corresponding tokens in Backend's operator-owned configuration. The script prompts without echoing them; other credentials are generated. Secret files contain no trailing newline, are root-owned `0400`, and are never committed or passed in container command arguments. The supervisor rejects business credentials in its environment.

```sh
python3 - <<'PY'
import getpass, secrets
from pathlib import Path
from urllib.parse import quote

paths = [Path('db-secrets')/name for name in ('postgres-password','migration-password','runtime-password','migration-database-url')]
paths += [Path('secrets')/name for name in ('database-url','backend-judge-token','judge-backend-token','runtime-token','scheduler-token','catalog-cursor-key')]
if any(path.exists() for path in paths):
    raise SystemExit('Existing credentials found; retain them and follow the upgrade procedure')
incoming = getpass.getpass('Backend -> Judge configured token: ')
outgoing = getpass.getpass('Judge -> Backend configured token: ')
def valid(token):
    return 32 <= len(token) <= 4096 and all(0x21 <= ord(c) <= 0x7e for c in token) and not token.upper().startswith(('GENERATED_','REPLACE_','EXAMPLE_','PLACEHOLDER','<'))
if not valid(incoming) or not valid(outgoing) or incoming == outgoing:
    raise SystemExit('Independent valid directional tokens are required')
values = {'backend-judge-token':incoming,'judge-backend-token':outgoing}
values.update({name:secrets.token_hex(32) for name in ('runtime-token','scheduler-token','catalog-cursor-key')})
if len(set(values.values())) != len(values):
    raise SystemExit('Credentials must be independent')
passwords = {name:secrets.token_hex(32) for name in ('postgres','migration','runtime')}
def write(path, value):
    path.write_text(value); path.chmod(0o400)
for name,value in passwords.items():
    write(Path('db-secrets')/(name+'-password'),value)
for name,value in values.items():
    write(Path('secrets')/name,value)
def dsn(role,password):
    return 'postgresql://'+role+':'+quote(password,safe='')+'@postgres:5432/judge?sslmode=verify-full&sslrootcert=/opt/startrack/db-ca.crt&connect_timeout=5'
write(Path('secrets/database-url'),dsn('judge_runtime',passwords['runtime']))
write(Path('db-secrets/migration-database-url'),dsn('judge_migration',passwords['migration']))
PY
```

The following file contains only nonsecret image/configuration identities. Checker and bridge hashes come from the published image's own recorded executable inventory.

```sh
JUDGE_CHECKER_SHA256=$(awk '$2=="/opt/startrack/libexec/default_validator" {print $1}' config/binaries.sha256)
JUDGE_MATURE_BRIDGE_SHA256=$(awk '$2=="/opt/startrack/libexec/problemtools-bridge.py" {print $1}' config/binaries.sha256)
test "${#JUDGE_CHECKER_SHA256}" -eq 64
test "${#JUDGE_MATURE_BRIDGE_SHA256}" -eq 64
cat > .deployment.env <<EOF
JUDGE_IMAGE=$JUDGE_IMAGE
JUDGE_IMAGE_DIGEST=$JUDGE_IMAGE_DIGEST
POSTGRES_IMAGE=$POSTGRES_IMAGE
JUDGE_CHECKER_SHA256=$JUDGE_CHECKER_SHA256
JUDGE_MATURE_BRIDGE_SHA256=$JUDGE_MATURE_BRIDGE_SHA256
JUDGE_ACQUISITION_PROXY=
EOF
chmod 0600 .deployment.env
```

`JUDGE_ACQUISITION_PROXY` may name an operator-owned, credential-free HTTP/HTTPS/SOCKS5 proxy reachable on the private network for the fixed upstream import repository. An internal Docker network has no direct internet egress; imports needing upstream fetches require that controlled route or remain unavailable. Do not attach a public network to sandbox workers or accept fetch destinations from callers.

## 3. Write the Compose configuration

Save the following as `/opt/startrack-judge-pr25/compose.server2.yaml`. The Judge API and PostgreSQL have no host-published ports. The upstream runtime remains on container loopback `127.0.0.1:5050`. The root supervisor alone reads the six fixed files and launches the existing nonroot process roles. The container has a read-only root filesystem, finite executable `/run`, no swap, an explicit capability list, the supplied profiles, and no Docker socket or host-root mount.

```yaml
name: startrack-judge-pr25
services:
  postgres:
    image: ${POSTGRES_IMAGE:?Set the pinned PostgreSQL image}
    environment:
      POSTGRES_USER: postgres
      POSTGRES_DB: judge
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres-password
      POSTGRES_INITDB_ARGS: --auth-local=peer --auth-host=scram-sha-256
    command:
      - postgres
      - -c
      - ssl=on
      - -c
      - ssl_cert_file=/tls/server.crt
      - -c
      - ssl_key_file=/tls/server.key
      - -c
      - hba_file=/etc/postgresql/pg_hba.conf
      - -c
      - max_connections=40
      - -c
      - shared_buffers=64MB
      - -c
      - log_statement=none
      - -c
      - log_min_error_statement=panic
      - -c
      - log_parameter_max_length=0
      - -c
      - log_parameter_max_length_on_error=0
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db-secrets/postgres-password:/run/secrets/postgres-password:ro
      - ./tls/postgres:/tls:ro
      - ./config/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro
    networks: [private]
    mem_limit: 512m
    memswap_limit: 512m
    cpus: 0.5
    pids_limit: 128
    healthcheck:
      test: [CMD-SHELL, "pg_isready -U postgres -d judge"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 15s
    restart: "no"
    stop_grace_period: 60s
    logging:
      driver: json-file
      options: {max-size: "5m", max-file: "2"}

  migrate:
    profiles: [operator]
    image: ${JUDGE_IMAGE:?Set the immutable service image}
    user: "0:0"
    entrypoint:
      - /usr/local/bin/python3
      - -c
      - "import os,sys; from pathlib import Path; os.environ['JUDGE_MIGRATION_DATABASE_URL']=Path('/run/migration/database-url').read_text(); os.execv('/usr/local/libexec/startrack/judge-migrate',['judge-migrate']+sys.argv[1:])"
    command: [status]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777"]
    volumes:
      - ./db-secrets/migration-database-url:/run/migration/database-url:ro
      - ./tls/ca.crt:/opt/startrack/db-ca.crt:ro
    networks: [private]
    mem_limit: 256m
    memswap_limit: 256m
    cpus: 0.5
    pids_limit: 64
    restart: "no"
    logging: {driver: none}

  judge:
    image: ${JUDGE_IMAGE:?Set the immutable service image}
    platform: linux/amd64
    user: "0:0"
    read_only: true
    cgroup: private
    cap_drop: [ALL]
    cap_add: [CHOWN, FOWNER, KILL, SETUID, SETGID, SYS_ADMIN, SYS_RESOURCE, SETFCAP]
    security_opt:
      - no-new-privileges:true
      - apparmor=startrack-v02
      - seccomp=./config/startrack-v02.seccomp.json
    environment:
      JUDGE_WORKER_IMAGE_DIGEST: ${JUDGE_IMAGE_DIGEST:?Set the actual manifest digest}
      JUDGE_CHECKER_SHA256: ${JUDGE_CHECKER_SHA256:?Set the image checker checksum}
      JUDGE_MATURE_BRIDGE_SHA256: ${JUDGE_MATURE_BRIDGE_SHA256:?Set the image bridge checksum}
      JUDGE_ACQUISITION_PROXY: ${JUDGE_ACQUISITION_PROXY:-}
    tmpfs:
      - /run:rw,nosuid,nodev,size=512m,nr_inodes=65536,mode=755
    volumes:
      - ./secrets:/run/secrets/startrack:ro
      - ./tls/ca.crt:/opt/startrack/db-ca.crt:ro
      - ./data/startrack:/var/lib/startrack
      - ./data/startrack-judger:/var/lib/startrack-judger
      - ./data/supervisor:/run/startrack-supervisor
    networks: [private]
    mem_limit: 3g
    memswap_limit: 3g
    cpus: 1
    pids_limit: 256
    restart: "no"
    stop_signal: SIGTERM
    stop_grace_period: 120s
    logging:
      driver: json-file
      options: {max-size: "5m", max-file: "2"}

networks:
  private:
    name: startrack-pr25-private
    internal: true
    attachable: true
volumes:
  postgres_data:
```

The service subgroups still carry the supervisor's compiled candidate limits; the outer 3 GiB / one CPU ceiling caps their aggregate. This configuration is for controlled low-volume candidate use and makes no maximum-package/concurrency claim. Do not increase limits on this shared host as a workaround for failures.

## 4. Start infrastructure, provision roles, and apply migrations

Define a shell helper so every command uses this deployment's file and environment. Keep this root session in `/opt/startrack-judge-pr25`.

```sh
dc() { docker compose --env-file .deployment.env -f compose.server2.yaml "$@"; }

# Output only success/failure; never print a rendered credential-bearing configuration.
dc config --quiet
dc up -d --wait --wait-timeout 90 postgres

# Dedicated database only: remove unsafe PUBLIC creation privileges before role provisioning.
dc exec -T --user postgres postgres psql -X -U postgres -d judge -v ON_ERROR_STOP=1 <<'SQL'
REVOKE ALL ON DATABASE judge FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL

# Feed the two passwords privately through stdin, then the pinned provisioning script.
{
  cat db-secrets/migration-password; printf '\n'
  cat db-secrets/runtime-password; printf '\n'
  cat source/scripts/provision-db.sql
} | dc exec -T --user postgres postgres sh -c '
  IFS= read -r JUDGE_MIGRATION_PASSWORD
  IFS= read -r JUDGE_RUNTIME_PASSWORD
  export JUDGE_MIGRATION_PASSWORD JUDGE_RUNTIME_PASSWORD
  exec psql -X -U postgres -d judge -v ON_ERROR_STOP=1
'

# One scoped migration process, using embedded forward SQL and the separate owner identity.
dc run --rm --no-deps migrate up -ceiling 5
dc exec -T --user postgres postgres psql -X -U postgres -d judge -v ON_ERROR_STOP=1 \
  < source/scripts/grant-runtime.sql
dc run --rm --no-deps migrate status
```

The status must show a clean applied level 5 with valid checksums. If provisioning, grants, TLS, or migration fails, stop here and keep Judge stopped. The migration command cannot lower the level; do not issue manual schema repair or edit shipped SQL to make startup succeed. Do not mount the operator/migration passwords into `judge`.

## 5. Connect Backend and manually start Judge

The callback destination is compiled as `http://backend:8081/internal/v2/events/judge`. Backend must be reachable with the `backend` DNS alias, listen on port 8081, use the agreed V0.2 integration, and carry matching directional S2S tokens. Its Judge base address is `http://judge:8082`; Frontend continues to call Backend. Configure that endpoint through Backend's own deployment mechanism, preserving its current networks and other settings.

Choose the existing Backend container deliberately from `docker ps`; the following prompts for its name and attaches only the dedicated private network. If it is already attached with the alias, skip `network connect`.

```sh
read -r -p 'Existing Backend container name: ' BACKEND_CONTAINER
docker network connect --alias backend startrack-pr25-private "$BACKEND_CONTAINER"

# Inspect Backend health through the candidate network without starting the supervisor.
docker run --rm --network startrack-pr25-private --read-only --cap-drop ALL \
  --security-opt no-new-privileges --memory 64m --memory-swap 64m --cpus 0.25 --pids-limit 32 \
  --entrypoint /usr/local/bin/python3 "$JUDGE_IMAGE" -c \
  'import urllib.request; r=urllib.request.urlopen("http://backend:8081/health",timeout=5); assert r.status==200; print("Backend health: HTTP 200")'

# Manual startup. This uses the image's existing HEALTHCHECK; it adds no execution tests.
dc up -d --no-deps --wait --wait-timeout 240 judge
```

A Backend health failure stops this sequence before Judge starts. Do not diagnose or repair Backend as a side effect of this runbook. If the Judge start/wait command fails, run `dc stop -t 120 judge`, keep Backend admission disabled, and retain the database/private storage. The supervisor's built-in readiness may run its required startup self-checks and will fail closed when isolation or a dependency is unavailable; never substitute mocks, privileged mode, unconfined profiles, or fallback execution.

No host API port is published. Docker 29's internal-network port publication behavior was implicated in the earlier failed smoke; this configuration uses the private network directly. No execution, import, callback acceptance, or restart qualification is implied by startup.

## 6. Health, access, and orderly stop

```sh
dc ps
JUDGE_CONTAINER=$(dc ps -q judge)
docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$JUDGE_CONTAINER"
JUDGE_PRIVATE_IP=$(docker inspect --format '{{(index .NetworkSettings.Networks "startrack-pr25-private").IPAddress}}' "$JUDGE_CONTAINER")
curl --fail --silent --show-error --max-time 5 "http://$JUDGE_PRIVATE_IP:8082/health"
```

Healthy readiness is HTTP 200 with this exact contract response:

```json
{"status":"ok","service":"judge-problem-service","contractVersion":"0.2.0","capabilities":{"catalog":true,"judge":true,"imports":true}}
```

An unhealthy Docker state, an exited container, HTTP 503, or a false required capability keeps new work disabled. `pg_isready` alone does not verify the runtime credential, TLS identity, or migration state. Keep diagnostics bounded and private: `dc logs --tail 50 judge`; root-only raw supervisor logs under `data/supervisor` must not be pasted into public Issues or used as public result DTOs. On host resource pressure or required isolation failure, stop the candidate.

For optional operator access, copy the private IP printed above to a local shell and open an SSH tunnel:

```sh
# Run locally, replacing the value with the server's actual current private IP.
JUDGE_PRIVATE_IP='ACTUAL_PRIVATE_CONTAINER_IP'
ssh -N -L "127.0.0.1:18082:$JUDGE_PRIVATE_IP:8082" server2
# In another local terminal:
curl --fail --max-time 5 http://127.0.0.1:18082/health
```

To stop or restart only this candidate, first disable Backend dispatch/import/publication to Judge through Backend's own maintenance mechanism. There is no invented Judge drain endpoint in this runbook. Stop with the existing graceful signal path; preserve durable tasks, leases, and callbacks for fenced recovery.

```sh
dc stop -t 120 judge
# A later manual restart, after prerequisites and admission controls are checked:
dc up -d --no-deps --wait --wait-timeout 240 judge
```

Do not run both old and new Judge workers against this database at once. The current image remains unqualified even when healthy; keep real untrusted workloads disabled until separately authorized qualification and integration acceptance exist.

## 7. Backup, upgrade, and rollback commands

Before changing an existing candidate, disable Backend admission, stop Judge, and take a coordinated database/private-object backup. The following creates a protected backup; it is not a claim that restore was tested.

```sh
dc stop -t 120 judge
JUDGE_BACKUP_DIR="backups/$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$JUDGE_BACKUP_DIR"
cp -a .deployment.env compose.server2.yaml config secrets db-secrets tls "$JUDGE_BACKUP_DIR/"
dc exec -T --user postgres postgres pg_dump -U postgres -d judge --format=custom \
  > "$JUDGE_BACKUP_DIR/judge.dump"
tar --numeric-owner -C data -czf "$JUDGE_BACKUP_DIR/private-and-dispatch.tar.gz" \
  startrack startrack-judger
dc run --rm --no-deps migrate status > "$JUDGE_BACKUP_DIR/migration-status.json"
chmod -R go-rwx "$JUDGE_BACKUP_DIR"
```

Record the previous immutable image and configuration, migration level, and recovery point before selecting a replacement. For an image upgrade, extract the replacement's profiles and checker/bridge checksums as in section 1, update all four image/checksum settings together in `.deployment.env`, apply only separately reviewed forward migrations, reapply runtime grants, and use section 5's manual startup. Recheck health before any separately authorized admission change. Do not treat a different image digest as already qualified.

**First-install rollback:** no earlier working Judge deployment is recorded. Stop this candidate and retain its persistent facts. Stop the dedicated database only if it serves this candidate alone. Leave Backend's original networks and configuration intact; remove the extra network attachment only if this runbook created it and no active Judge traffic needs it.

```sh
dc stop -t 120 judge
# Optional for this dedicated candidate database:
dc stop -t 60 postgres
# Optional only for the attachment made in section 5:
docker network disconnect startrack-pr25-private "$BACKEND_CONTAINER"
```

**Application rollback with a recorded predecessor:** use these commands only when the previous binary is explicitly compatible with the currently applied schema, frozen task/runtime identities, and retained artifacts. Select the actual backup directory from above; do not guess a previous image tag. Restoring the nonsecret environment and profiles here does not rewind the database or overwrite secret/object history.

```sh
dc stop -t 120 judge
JUDGE_PREVIOUS_BACKUP='backups/ACTUAL_PRE_UPGRADE_BACKUP_DIRECTORY'
cp "$JUDGE_PREVIOUS_BACKUP/.deployment.env" .deployment.env
cp "$JUDGE_PREVIOUS_BACKUP/compose.server2.yaml" compose.server2.yaml
cp -a "$JUDGE_PREVIOUS_BACKUP/config/." config/
apparmor_parser --replace config/startrack-v02.apparmor
dc pull judge
dc up -d --no-deps --wait --wait-timeout 240 judge
# Repeat section 6's health commands before any admission change.
```

If no compatible predecessor exists, leave Judge stopped and retain the current database/objects for a separately reviewed forward fix. A database restore is a separate, explicitly authorized recovery operation requiring a coordinated DB/object point and Backend reconciliation; do not restore this dump over live history to make an old binary start. Never run `down --volumes`, delete the private storage, clear task/outbox rows, lower migrations, or force GitHub protections as a rollback shortcut.

No deployment, credentials, database migration, server health probe, or rollback command in this guide was automatically executed on server2.
