# Contributing

## Prerequisites

- JDK 11
- Maven 3.6+

## Local builds

```
# Windows
mvn -B "-Dgpg.skip=true" clean verify

# macOS / Linux
mvn -B -Dgpg.skip=true clean verify
```

## Local SNAPSHOT install

To install to your local Maven repository without signing:

```
mvn -B "-Dgpg.skip=true" clean install
```

## Running tests

Tests run automatically during `verify`. To skip:

```
mvn -B "-Dgpg.skip=true" -DskipTests clean package
```

## Code style

- Java 11 source and target (`maven.compiler.release=11`)
- All source files must be ASCII only
- Apache Santuario `xmlsec` 4.0.4

## Pull requests

Target the `java-11` branch. Ensure `mvn verify` passes before opening a PR.

## Copyright

Copyright 2009 NEHTA. Copyright 2021-2026 ADHA. Apache License 2.0 - see **LICENSE.txt**.
