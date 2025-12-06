# http_hardening_check.nse

Minimal, fast Nmap NSE script to verify basic HTTP hardening on web targets.

**Checks**

* Presence of security headers on `/` (configurable):

  * **HSTS** → `strict-transport-security`
  * **CSP** → `content-security-policy`
  * **XFO** → `x-frame-options`
* Optional probe of **`/admin`** to flag if exposed (HTTP 200) or protected (401/403).

Outputs a single, grep-friendly finding line per host/port.

---

## Why

When you’re assessing many lab hosts, you often need a quick signal for baseline hardening and an obvious risky path. This NSE makes one request to `/` (HEAD → GET fallback), optionally checks `/admin`, then prints a concise line you can drop into notes, CSVs, or dashboards.

---

## Install

1. Save as `http_hardening_check.nse`.
2. Copy to Nmap’s scripts directory and refresh the DB:

```bash
sudo cp http_hardening_check.nse /usr/share/nmap/scripts/
sudo chmod 644 /usr/share/nmap/scripts/http_hardening_check.nse
sudo nmap --script-updatedb
```

3. Verify registration:

```bash
sudo nmap --script-help http_hardening_check
```

> **Note:** You can also run it from a custom path via `--script /full/path/http_hardening_check.nse`.

---

## Usage

Basic (80/443):

```bash
sudo nmap -Pn -sV -p80,443 <target> \
  --script http_hardening_check
```

Specify headers/paths/host and keep output brief (default):

```bash
sudo nmap -Pn -sV -p80,443 <target> \
  --script http_hardening_check \
  --script-args "http_hardening_check.headers=hsts,csp,xfo,http_hardening_check.paths=/,/admin,http_hardening_check.brief=true"
```

Multiple hosts:

```bash
sudo nmap -Pn -sV -p80,443 10.20.30.21 10.20.30.31 10.20.30.41 \
  --script http_hardening_check
```

Custom virtual host (Host header + SNI):

```bash
--script-args "http_hardening_check.host=app.lab.local"
```

---

## Script Arguments

| Argument                       | Type   |        Default | Description                                                                                                                                                     |
| ------------------------------ | ------ | -------------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `http_hardening_check.headers` | CSV    | `hsts,csp,xfo` | Required headers. Shorthands: `hsts` → `strict-transport-security`, `csp` → `content-security-policy`, `xfo` → `x-frame-options`. Full names are also accepted. |
| `http_hardening_check.paths`   | CSV    |            `/` | Paths to request. Include `/admin` to test exposure.                                                                                                            |
| `http_hardening_check.host`    | String |       *(none)* | Virtual host to send in `Host` header and use for SNI.                                                                                                          |
| `http_hardening_check.brief`   | Bool   |         `true` | Single concise line (true) vs. multi-line (false).                                                                                                              |

---

## Example Output

**Hardened host (OK headers, no `/admin`):**

```
| http_hardening_check:
|   FINDING: missing=[] admin=[]
|_  target=10.20.30.21 port=80
```

**Vulnerable host (all 3 headers missing):**

```
| http_hardening_check:
|   FINDING: missing=[strict-transport-security,content-security-policy,x-frame-options] admin=[]
|_  target=10.20.30.31 port=80
```

**`/admin` exposed:**

```
| http_hardening_check:
|   FINDING: missing=[content-security-policy] admin=[/admin -> 200 (exposed)]
|_  target=10.20.30.41 port=80
```

**No HTTP response:**

```
| http_hardening_check:
|_  FINDING: missing=[*no-response*] admin=[]
```

---

## Quick Self‑Test (Kali)

Start a throwaway server:

```bash
python3 -m http.server 8080
```

Scan:

```bash
sudo nmap -Pn -sV -p8080 127.0.0.1 \
  --script http_hardening_check \
  --script-args "http_hardening_check.headers=hsts,csp,xfo,http_hardening_check.paths=/,/admin"
```

Expect all three headers missing; `/admin` → 404.

---

## Windows / IIS Lab (Target 2–style)

Enable IIS and bind to LAB IP:

```powershell
# Core IIS
dism /online /enable-feature /featurename:IIS-WebServer /all /norestart
# Optional niceties
dism /online /enable-feature /featurename:IIS-DefaultDocument /norestart
dism /online /enable-feature /featurename:IIS-StaticContent /norestart

Import-Module WebAdministration

# Bind HTTP/HTTPS to LAB IP
Get-WebBinding -Name "Default Web Site" -Protocol http | Remove-WebBinding
New-WebBinding  -Name "Default Web Site" -Protocol http  -IPAddress 10.20.30.31 -Port 80

$cert = New-SelfSignedCertificate -DnsName "target2.lab" -CertStoreLocation Cert:\LocalMachine\My
New-WebBinding  -Name "Default Web Site" -Protocol https -IPAddress 10.20.30.31 -Port 443
New-Item "IIS:\SslBindings\10.20.30.31!443" -Thumbprint $cert.Thumbprint -SSLFlags 0 | Out-Null

'<!doctype html><title>target-2</title><h1>Hello from Target 2</h1>' |
  Set-Content -Encoding utf8 C:\inetpub\wwwroot\index.html

# Allow inbound 80/443
netsh advfirewall firewall add rule name="Lab HTTP 80"  dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Lab HTTPS 443" dir=in action=allow protocol=TCP localport=443
```

**Keep it vulnerable (to see missing headers):**

* Don’t add custom response headers for HSTS/CSP/XFO.
* Confirm with `curl -I http://10.20.30.31/` → headers absent.

**Harden later (to see script flip to `missing=[]`):**

```powershell
# HSTS (use only with valid HTTPS)
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.webServer/httpProtocol/customHeaders" `
  -name "." -value @{name='Strict-Transport-Security';value='max-age=31536000; includeSubDomains'}

# CSP
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.webServer/httpProtocol/customHeaders" `
  -name "." -value @{name='Content-Security-Policy';value="default-src 'self'"}

# X-Frame-Options
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.webServer/httpProtocol/customHeaders" `
  -name "." -value @{name='X-Frame-Options';value='DENY'}
```

**Remove again to restore vulnerabilities:**

```powershell
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.webServer/httpProtocol/customHeaders" `
  -name "." -AtElement @{name='Strict-Transport-Security'}
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.webServer/httpProtocol/customHeaders" `
  -name "." -AtElement @{name='Content-Security-Policy'}
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
  -filter "system.webServer/httpProtocol/customHeaders" `
  -name "." -AtElement @{name='X-Frame-Options'}
```

---

## Interpreting Results

* `missing=[]` — All required headers present on `/`.
* `missing=[…]` — Listed headers are absent; add them at the origin or trusted reverse proxy.
* `admin=[/admin -> 200 (exposed)]` — Sensitive path exposed; restrict or remove.
* `*no-response*` — Port closed/filtered or no HTTP service.

### Header quick reference

* **HSTS** (Strict-Transport-Security): forces HTTPS; mitigates SSL-strip and cookie leak over HTTP.

  * Example: `Strict-Transport-Security: max-age=31536000; includeSubDomains`
* **CSP** (Content-Security-Policy): reduces XSS and data exfil by limiting allowed sources.

  * Example: `Content-Security-Policy: default-src 'self'`
* **XFO** (X-Frame-Options): stops clickjacking via iframes.

  * Example: `X-Frame-Options: DENY`

---

## Troubleshooting

* **`INTERNAL ERROR: variable 'safeip'/'toip' is not declared`** — Update the script file to the latest version in this repo and re-run:

  ```bash
  sudo cp http_hardening_check.nse /usr/share/nmap/scripts/
  sudo nmap --script-updatedb
  ```
* **`…did not match a category, filename, or directory`** — Wrong name/path. Use `--script http_hardening_check` after copying to script dir, or pass full path.
* **No findings on closed ports** — The script runs when `shortport.http` matches an HTTP service. Use `-sV` and scan open HTTP(S) ports.
* **Need more debug** —

  ```bash
  sudo nmap -Pn -sV -p80,443 <target> \
    --script http_hardening_check -d2 --script-trace
  ```

---

## Limitations

* Single-page probe: checks `/` (plus optional `/admin`) — no crawling.
* Presence-only: does not validate **correctness** of policy values.
* HSTS is meaningful only with correctly-served HTTPS.
* Falls back to `GET` when `HEAD` is blocked.

---

## License

Same as Nmap — see the Nmap license: [https://nmap.org/book/man-legal.html](https://nmap.org/book/man-legal.html)

---

## Credits

Built for a dual-NIC lab (LAB + NAT), isolated scanners on VLAN 30, and explicit host firewalls.

**Authors:** Vijay & ChatGPT
