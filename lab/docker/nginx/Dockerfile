FROM nginx:1.27-alpine

# Self-signed certificate generated at build time; no key is stored in the repo.
RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/certs \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=hardened.lab" \
      -addext "subjectAltName=DNS:hardened.lab,DNS:weak.lab,DNS:spa.lab" \
      -keyout /etc/nginx/certs/lab.key -out /etc/nginx/certs/lab.crt 2>/dev/null \
 && rm /etc/nginx/conf.d/default.conf

# Content. The weak site deliberately serves a git HEAD file, a .env file with
# fake values and a browsable directory.
RUN mkdir -p /srv/hardened /srv/weak/.git /srv/weak/files /srv/spa \
 && echo '<!doctype html><title>hardened</title><h1>hardened.lab</h1>' > /srv/hardened/index.html \
 && echo '<!doctype html><title>weak</title><h1>weak.lab</h1>' > /srv/weak/index.html \
 && echo 'ref: refs/heads/main' > /srv/weak/.git/HEAD \
 && printf 'APP_ENV=lab\nDB_PASSWORD=not-a-real-secret\n' > /srv/weak/.env \
 && echo 'lab file' > /srv/weak/files/readme.txt \
 && echo '<!doctype html><title>spa</title><div id="app">single page app</div>' > /srv/spa/index.html

COPY lab.conf /etc/nginx/conf.d/lab.conf
