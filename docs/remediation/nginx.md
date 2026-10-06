# nginx

The Docker lab's [`hardened.lab`](../../lab/docker/nginx/lab.conf) server is a working example that scores 100/A.

## Redirect and HSTS

```nginx
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;          # no-https-redirect
}

server {
    listen 443 ssl;
    server_name example.com;
    # hsts-missing, hsts-short-max-age, hsts-no-subdomains
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

`always` adds the header to error responses too. Without it, nginx only adds headers to 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308 responses.

## The add_header inheritance trap

`add_header` directives are inherited from the enclosing block **only if the current block has none of its own**. One `add_header` inside a `location` silently drops every server-level security header for that location. Put shared headers in a file and include it wherever you add others:

```nginx
# /etc/nginx/snippets/security-headers.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

```nginx
location /downloads/ {
    include snippets/security-headers.conf;
    add_header Content-Disposition "attachment";
}
```

The scanner judges one page per port (default `/`); scan other paths with `http-hardening-check.path=/downloads/` to catch this.

## Version disclosure

```nginx
server_tokens off;                 # info-disclosure (Server: nginx/1.x)
proxy_hide_header X-Powered-By;    # tech-disclosure / info-disclosure from upstream apps
fastcgi_hide_header X-Powered-By;  # PHP-FPM
```

## Cookies set by the application

Fix flags in the application where possible. As a proxy-level fallback (nginx 1.19.3+):

```nginx
proxy_cookie_flags ~ secure httponly samesite=lax;   # cookie-no-secure, cookie-no-httponly, cookie-no-samesite
```

Exclude cookies that scripts must read (for example a CSRF token) by naming cookies explicitly instead of `~`.

## CORS

Never echo `$http_origin` unconditionally (that is `cors-reflected-credentials`). Use an allowlist:

```nginx
map $http_origin $cors_origin {
    default "";
    "https://app.example.com" $http_origin;
}

server {
    add_header Access-Control-Allow-Origin $cors_origin always;   # empty value: header not sent
    add_header Access-Control-Allow-Credentials "true" always;
    add_header Vary "Origin" always;
}
```

## Exposure

```nginx
autoindex off;                                   # directory-listing (off is the default)
location ~ /\.(?!well-known/) { deny all; }      # exposed-git, exposed-env, exposed-ds-store
```

nginx answers `TRACE` with 405 by default, so `trace-enabled` does not apply.
