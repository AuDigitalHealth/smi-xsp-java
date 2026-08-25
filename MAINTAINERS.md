# Maintainers

## Artifact

`au.gov.nehta:smi-xsp` - published to Maven Central via Sonatype Central Portal.

## Version lines

| Version | Java | Branch |
| ---- | ---- | ---- |
| **8.0.0** | 8 / javax | `java-8` |
| **11.0.0.1** | 11 / Jakarta | `java-11` |

## Key dependency

| Property | Value |
| ---- | ---- |
| `xmlsec.version` | `2.3.5` (last 2.3.x; Java 8 compatible) |

To update: change `xmlsec.version` in `pom.xml` properties, run `mvn verify`, confirm no Jakarta leaks via `mvn dependency:tree`.

## Release process

1. Ensure `java-8` branch is green.
2. `mvn -B release:prepare release:perform -Prelease` (GPG key required).
3. Sonatype Central Portal auto-publishes after closing.

## Publishing credentials

`settings.xml` with `<server id="central">` - see `settings.xml.example`.

## Copyright

Copyright 2009 NEHTA. Copyright 2021-2026 ADHA. Apache License 2.0 - see **LICENSE.txt**.
