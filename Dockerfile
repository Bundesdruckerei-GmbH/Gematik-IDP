#  Copyright 2026 Bundesdruckerei GmbH
#  For the license, see the accompanying file LICENSE.md

FROM quay.io/keycloak/keycloak:26.5.6 AS builder

WORKDIR /opt/keycloak
# for demonstration purposes only, please make sure to use proper certificates in production instead
RUN keytool -genkeypair \
    -storepass password \
    -storetype PKCS12 \
    -keyalg RSA \
    -keysize 2048 \
    -dname "CN=server" \
    -alias server \
    -ext "SAN:c=DNS:localhost,IP:127.0.0.1" \
    -keystore conf/server.keystore

COPY /target/gematik-idp-*.jar /opt/keycloak/providers/
COPY /themes/gematik-idp /opt/keycloak/themes/gematik-idp

# Enable health and metrics support
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Configure a database vendor
ENV KC_DB=postgres
ENV KC_HTTP_RELATIVE_PATH=/auth

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh start"]
