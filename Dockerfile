FROM quay.io/keycloak/keycloak:20.0.5 as builder

WORKDIR /opt/keycloak
# for demonstration purposes only, please make sure to use proper certificates in production instead
RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore
RUN /opt/keycloak/bin/kc.sh build

COPY /target/gematik-idp-*.jar /providers/
COPY /themes/gematik-idp /gematik-idp

# Enable health and metrics support
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Configure a database vendor
ENV KC_DB postgres
ENV KC_SPI_THEME_DEFAULT keycloak
ENV KC_SPI_THEME_ADMIN keycloak
ENV KC_FEATURES "admin"
ENV KC_FEATURES_DISABLED "admin2"
ENV KC_HTTP_RELATIVE_PATH /auth

ENTRYPOINT ["/opt/keycloak/bin/kc.sh start"]
