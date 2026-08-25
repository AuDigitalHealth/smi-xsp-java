# Changelog

## 21.0.0

- Java 21 release line (`maven.compiler.release=21`)
- Apache Santuario `xmlsec` 4.0.4

## 17.0.0

- Java 17 release line (`maven.compiler.release=17`)
- Apache Santuario `xmlsec` 4.0.4

## 11.0.0

- Java 11 release line (`maven.compiler.release=11`)
- Apache Santuario `xmlsec` 4.0.4
- Java 11 idioms in vendored utils and XSP services (`List.of`, `EnumMap`, UTF-8 DOM serialise, `getSubjectX500Principal`)
- Removed unused `jakarta.xml.bind-api` and dead `JaxbUtils` copy

## 8.0.0

- Version line aligned to Java 8 (`maven.compiler.release=8`)
- Distribution migrated to Sonatype Central Portal (`central-publishing-maven-plugin`)
- Updated `xmlsec` to 2.3.5 (last 2.3.x compatible with Java 8)
- Plugin versions updated: compiler 3.15.0, surefire 3.5.5, javadoc 3.12.0, source 3.4.0, gpg 3.2.8
- GPG signing skipped by default; enabled via `-Prelease`

## 1.2.1

- Converted to Maven
- Replaced external dependencies with Maven ones

## 1.2.0

- Added support for JVM 1.7_21+

## 1.0.9

- Added CertificateUtils#checkJCEpolicyIsUnlimited

## 1.0

- Initial release

## Copyright

Copyright 2009 NEHTA. Copyright 2021-2026 ADHA. Apache License 2.0 - see **LICENSE.txt**.
