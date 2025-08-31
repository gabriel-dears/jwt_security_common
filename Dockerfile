FROM maven:3.9.8-eclipse-temurin-21 AS build

WORKDIR /app
COPY jwt_security_common /app/jwt_security_common
