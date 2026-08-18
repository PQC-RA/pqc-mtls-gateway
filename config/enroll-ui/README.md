# Public enrollment bundle (mounted read-only into the gateway)

This directory is bind-mounted read-only into the gateway container at
`/etc/nginx/enroll-ui` and served on the public `:8443` server block
(`root /etc/nginx/enroll-ui;`).

Only the **public enrollment** bundle belongs here, `enroll.html` and its
`assets/`, never the admin console. The bundle is built on the UI machine and
copied in by prompt `18`. Until then this dir is empty and the page returns 404
(the nginx/compose wiring in prompt `17` lands independently).
