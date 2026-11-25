# CertForge
A Web-Based Certificate Authority with Live Revocation

## Setup

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```
python run.py
```

Opens the dashboard at `http://127.0.0.1:5000`. The first run creates the
root CA and the database under `instance/`.

## Demo: HTTPS trust chain and live revocation

With the main app having been run at least once:

```
python demo/serve.py
```

This issues `localhost` its own certificate through CertForge and serves a
page over `https://localhost:8443`.

1. Download the root CA certificate from the dashboard (or `/root.pem`) and
   import it into your browser's or OS's trust store.
2. Load `https://localhost:8443` — it should be trusted, with no warning.
3. In the admin panel, revoke the certificate issued for `localhost`.
4. Browsers don't check CRLs for locally-trusted roots, so the page may
   still load without a warning. The revocation is still live and real —
   confirm it with the `/verify` page (paste `instance/demo.pem`) or:
   ```
   openssl verify -CAfile instance/ca/root.pem -crl_check -CRLfile instance/ca/crl.pem instance/demo.pem
   ```
   Both report the certificate as revoked.
5. To see the warning a browser *does* show, run
   `python demo/serve.py --port 8444 --self-signed` and load
   `https://localhost:8444` — this certificate isn't issued by CertForge at
   all, so it's untrusted.

## Tests

```
python -m pytest
```
