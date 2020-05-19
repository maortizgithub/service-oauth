FROM openjdk:14
VOLUME /tmp
EXPOSE 9100
ADD ./target/service-oauth-0.0.1-SNAPSHOT.jar service-oauth.jar
ENTRYPOINT ["java", "-jar", "/service-oauth.jar"]