# Apache httpd

Requires `mod_headers` (and `mod_rewrite` or `mod_alias` for the redirect). The Docker lab's [`mixed.lab`](../../lab/docker/apache/Dockerfile) shows the problems this page fixes.

## Redirect and HSTS

```apache
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/                 # no-https-redirect
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    # hsts-missing, hsts-short-max-age, hsts-no-subdomains
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
```

`Header always set` applies to error responses as well; plain `Header set` does not.

## Response headers

```apache
Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
```

A `Content-Security-Policy-Report-Only` header alone is `csp-report-only`: switch to the enforcing header once reports are clean.

## Version disclosure

```apache
ServerTokens Prod          # info-disclosure (Server: Apache/2.4.x (Unix))
ServerSignature Off
Header always unset X-Powered-By
```

For PHP also set `expose_php = Off` in `php.ini`; `Header unset` cannot always remove headers added late by some handlers.

## Exposure

```apache
TraceEnable Off                                  # trace-enabled (Apache enables TRACE by default)

<Directory "/var/www/html">
    Options -Indexes                             # directory-listing
</Directory>

<Location "/server-status">                      # exposed-server-status
    SetHandler server-status
    Require local
</Location>

<FilesMatch "^\.">                               # exposed-env, exposed-ds-store
    Require all denied
</FilesMatch>
RedirectMatch 404 /\.git                         # exposed-git
```

## Cookies

Set `Secure`, `HttpOnly` and `SameSite` in the application. A proxy-level rewrite such as `Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure"` appends attributes twice if the application already sets them, and applies HttpOnly to cookies scripts may need; use it only as a temporary measure and scope it to known cookie names.
