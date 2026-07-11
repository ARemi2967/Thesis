FROM eclipse-temurin:8u432-b06-jdk-jammy

WORKDIR /app

# Directories for MCP output (mounted from host at runtime)
RUN mkdir -p /data/gadget-dependencies /data/generated-env

COPY target/deserialization-gateway-1.0.0.jar app.jar

EXPOSE 8080

# Point ChainService at the mounted MCP data root (BS5)
ENV BS5_ROOT=/data

CMD ["java", "-jar", "app.jar"]
