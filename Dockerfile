FROM quay.io/keycloak/keycloak:23.0.3 as builder

ENV KC_DB=dev-file

#COPY ./build/install/keycloak-customer-number-login/*.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

#ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "--debug", "start-dev", "--import-realm"]