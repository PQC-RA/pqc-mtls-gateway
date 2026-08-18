FROM nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752

# PKI distribution merely serves static files from /var/www/pki
# We replace the default config to just serve that folder
RUN echo "server { listen 8090; root /var/www/pki; location / { autoindex on; } }" > /etc/nginx/conf.d/default.conf

EXPOSE 8090
