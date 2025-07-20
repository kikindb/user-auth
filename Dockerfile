# Stage 1: Build the application
# Changed base image to one that includes Maven
FROM maven:3.9.6-eclipse-temurin-21-jammy AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the Maven build file (pom.xml) and download dependencies
# This step is cached if pom.xml doesn't change, speeding up subsequent builds
COPY pom.xml .
# Added -X for debug output to help diagnose dependency download issues
RUN mvn dependency:go-offline -X

# Copy the rest of the application source code
COPY src ./src

# Build the Spring Boot application into a JAR file
# -DskipTests skips running tests during the build
RUN mvn clean install -DskipTests

# Stage 2: Create the final runtime image
# Use a smaller JRE base image for the final production image
FROM eclipse-temurin:21-jre-jammy

# Set the working directory
WORKDIR /app

# Copy the built JAR file from the 'build' stage
# The JAR file is typically named target/<artifact-id>-<version>.jar
# You might need to adjust the exact JAR name based on your pom.xml's artifactId and version
COPY --from=build /app/target/*.jar app.jar

# Expose the port your Spring Boot application runs on
EXPOSE 8080

# Define the command to run the application
# Use 'java -jar' to run the Spring Boot executable JAR
# You can add JVM arguments here, e.g., -Xmx512m for memory limits
ENTRYPOINT ["java", "-jar", "app.jar"]

# Optional: Set active Spring profile via environment variable
# This allows you to easily switch profiles (e.g., 'prod', 'dev', 'test') during runtime
# You would set this when running the container:

# ENV SPRING_PROFILES_ACTIVE=default
