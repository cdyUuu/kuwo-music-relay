FROM php:8.2-cli

LABEL org.opencontainers.image.title="Kuwo Music Relay Decrypt Server"
LABEL org.opencontainers.image.description="PHP relay server for real-time decryption and streaming of Kuwo Music encrypted audio"
LABEL org.opencontainers.image.licenses="MIT"

# Install cURL extension (usually pre-installed, but ensure)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4-openssl-dev \
    && docker-php-ext-install curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /var/www/html

# Copy the server file
COPY decrypt.php /var/www/html/decrypt.php

# Create cache directory
RUN mkdir -p /tmp/mflac_relay && chmod 777 /tmp/mflac_relay

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD php -r 'echo "OK";' || exit 1

# Run PHP built-in server
CMD ["php", "-S", "0.0.0.0:8080", "/var/www/html/decrypt.php"]
