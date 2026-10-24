# systemd integration

Drop `logfold.service` into `/etc/systemd/system/` and tune the
`ExecStart` for your fleet.

## One-time setup

```sh
# Dedicated service user. No login shell, no home.
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/logfold -M logfold

# State directory for the --state snapshot (v0.10+).
sudo install -d -o logfold -g logfold -m 0750 /var/lib/logfold

# Optional patterns dir if you ship extra bundles.
sudo install -d -o root -g root -m 0755 /etc/logfold/patterns

# Grant read access to the specific logs you want to fold.
sudo setfacl -m u:logfold:r /var/log/auth.log
sudo setfacl -m u:logfold:r /var/log/nginx/access.log
# OR add to adm / systemd-journal if you want everything under /var/log.
sudo usermod -aG adm,systemd-journal logfold
```

## Install the unit

```sh
sudo cp contrib/systemd/logfold.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now logfold.service

sudo journalctl -u logfold -f
```

## Customising ExecStart

Create a drop-in instead of editing the shipped unit:

```sh
sudo systemctl edit logfold.service
```

Example drop-in content for a webhook deployment:

```ini
[Service]
# Clear the shipped ExecStart and define our own.
ExecStart=
ExecStart=/usr/local/bin/logfold --no-tui --ndjson --follow \
    --webhook https://hooks.example.com/logfold \
    --webhook-min-score 70 \
    --iocs /etc/logfold/iocs.csv \
    --state /var/lib/logfold/state.bin \
    /var/log/auth.log /var/log/nginx/access.log journald:sshd

# Enable network for --webhook.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

See `SECURITY.md` for the full threat model and deployment
recommendations.
