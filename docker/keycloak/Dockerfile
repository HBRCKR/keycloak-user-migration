ARG KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:21.0.2

FROM maven:3.9.1-amazoncorretto-17 as builder
COPY pom.xml /tmp/
COPY src /tmp/src
WORKDIR /tmp/
RUN mvn clean package

FROM $KEYCLOAK_IMAGE
USER root
COPY --from=builder /tmp/target/*.jar /opt/keycloak/providers/app.jar
USER 1000

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]