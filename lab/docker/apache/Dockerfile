FROM httpd:2.4-alpine

# mixed.lab: a typical half-hardened Apache. Intentionally insecure test target.
RUN printf '%s\n' \
      'ServerTokens Full' \
      'TraceEnable On' \
      'Header always set Content-Security-Policy-Report-Only "default-src '"'"'self'"'"'"' \
      'Header always set X-Frame-Options "SAMEORIGIN"' \
      'Header always set X-Content-Type-Options "nosniff"' \
      'Header always set Referrer-Policy "no-referrer-when-downgrade"' \
      '<Location "/server-status">' \
      '    SetHandler server-status' \
      '    Require all granted' \
      '</Location>' \
    >> /usr/local/apache2/conf/httpd.conf \
 && echo '<!doctype html><title>mixed</title><h1>mixed.lab</h1>' > /usr/local/apache2/htdocs/index.html
