# Public enrollment bundle (mounted read-only into the gateway)

This directory is bind-mounted read-only into the gateway container at
`/etc/nginx/enroll-ui` and served on the public `:8443` server block
(`root /etc/nginx/enroll-ui;`).

Only a **public enrollment** bundle belongs here, `enroll.html` and its
`assets/`, never the admin console.

No bundle ships with this repository. The `:8443` listener serves this directory
if you mount one and returns 404 otherwise; the CSR-signing route it proxies
works either way, and `scripts/issue-cert.sh` uses that route directly without
a browser.
