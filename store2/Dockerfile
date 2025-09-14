#############################################
# First stage: Build the application
FROM registry.access.redhat.com/ubi8/openjdk-21:1.20 AS builder

WORKDIR /app

COPY --chmod=755 --chown=jboss:jboss ./gradlew /app/gradlew
COPY --chmod=755 --chown=jboss:jboss ./gradle /app/gradle
COPY --chmod=644 --chown=jboss:jboss ./build.gradle.kts /app/build.gradle.kts
COPY --chmod=644 --chown=jboss:jboss ./settings.gradle.kts /app/settings.gradle.kts
COPY --chmod=644 --chown=jboss:jboss ./gradle.properties /app/gradle.properties
COPY --chmod=755 --chown=jboss:jboss ./src /app/src

# Run the build
RUN ./gradlew build
#############################################

# Second stage: Create the final image
FROM registry.access.redhat.com/ubi8/openjdk-21:1.20

ENV LANGUAGE='en_US:en'

# Copy the build artifacts from the builder stage
COPY --chmod=755 --chown=jboss:jboss --from=builder /app/build/quarkus-app/lib/ /deployments/lib/
COPY --chmod=755 --chown=jboss:jboss --from=builder /app/build/quarkus-app/*.jar /deployments/
COPY --chmod=755 --chown=jboss:jboss --from=builder /app/build/quarkus-app/app/ /deployments/app/
COPY --chmod=755 --chown=jboss:jboss --from=builder /app/build/quarkus-app/quarkus/ /deployments/quarkus/

# Fix permissions of volume
RUN mkdir -m 755 /deployments/db
RUN mkdir -m 755 /deployments/config
RUN chown -R jboss:jboss /deployments

# Copy application properties
COPY --chmod=644 --chown=jboss:jboss ./deployment-application.properties /deployments/config/application.properties

EXPOSE 8080
USER jboss
ENV JAVA_OPTS_APPEND="-Dquarkus.http.host=0.0.0.0 -Djava.util.logging.manager=org.jboss.logmanager.LogManager"
ENV JAVA_APP_JAR="/deployments/quarkus-run.jar"

ENTRYPOINT [ "/opt/jboss/container/java/run/run-java.sh" ]