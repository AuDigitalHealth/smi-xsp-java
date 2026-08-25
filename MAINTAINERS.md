# Maintainers

## Artifact

`au.gov.nehta:smi-xsp` - published to Maven Central via Sonatype Central Portal.

## Version lines

| Version    | Java      | Branch    |
| ---------- | --------- | --------- |
| **8.0.0**  | 8 / javax | `java-8`  |
| **11.0.0** | 11        | `java-11` |
| **17.0.0** | 17        | `java-17` |
| **21.0.0** | 21        | `java-21` |

## Key dependency

| Property         | Value   |
| ---------------- | ------- |
| `xmlsec.version` | `4.0.4` |

To update: change `xmlsec.version` in `pom.xml` properties and run `mvn verify`.

## Release process

1. Ensure `java-21` branch is green.
2. `mvn -B release:prepare release:perform -Prelease` (GPG key required).
3. Sonatype Central Portal auto-publishes after closing.

## Publishing credentials

`settings.xml` with `<server id="central">` - see `settings.xml.example`.

## Copyright

Copyright 2009 NEHTA. Copyright 2021-2026 ADHA. Apache License 2.0 - see **LICENSE.txt**.
