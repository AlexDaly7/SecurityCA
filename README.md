# SecurityCA

A project made for the Security Fundamentals and Development module.

## Requirements

- Java 25
- Maven (bundled with IntelliJ, or install separately)
- IntelliJ IDEA >= 2025.3 (if editing GUI)

## Running

### In IntelliJ

Use one of following run configurations:

- **Listen**: wait for connection on port 5000
- **Connect (localhost)**: attempt to connect to localhost on port 5000
- **Package to jar**: builds a jar to run outside IntelliJ

### Via command line

Build the jar:

```bash
mvn clean package
```

Listen for connection:

```bash
java -jar target/SecurityCA-1.0-SNAPSHOT.jar
```

Or connect to a listener:

```bash
java -jar target/SecurityCA-1.0-SNAPSHOT.jar <ip-address>
```

### Prebuilt jar

A jar can be downloaded from the build action artifacts section [here](https://github.com/AlexDaly7/SecurityCA/actions/workflows/build.yml).

## Tests

Test can be run with:

```bash
mvn test
```