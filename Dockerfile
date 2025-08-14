# Dockerfile

FROM eclipse-temurin:21

ARG JAR_FILE=target/CodeArenaBff-0.0.1-SNAPSHOT.jar

COPY ${JAR_FILE} CodeArenaBff-0.0.1-SNAPSHOT.jar

ENTRYPOINT ["java", "-jar", "/CodeArenaBff-0.0.1-SNAPSHOT.jar"]