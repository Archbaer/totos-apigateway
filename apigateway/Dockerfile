FROM openjdk:21-slim
VOLUME /tmp
COPY target/apigateway-*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]