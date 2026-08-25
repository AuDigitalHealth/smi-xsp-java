# smi-xsp - XML Secured Payload Profiles

Java implementation of XML Secured Payload Profiles for the Australian Digital Health Agency.

## Dependency (Maven Central)

```xml
<dependency>
    <groupId>au.gov.nehta</groupId>
    <artifactId>smi-xsp</artifactId>
    <version>21.0.0</version>
</dependency>
```

## Runtime requirements

- Java 21 or later
- Apache Santuario `xmlsec` 4.0.4 arrives transitively with this artifact

## Versioning

| Version | Java | XML security stack |
| ------- | ---- | ------------------ |
| **8.0.0** | 8 | Apache Santuario `xmlsec` 2.3.x |
| **11.0.0** | 11 | Apache Santuario `xmlsec` 4.0.4 |
| **17.0.0** | 17 | Apache Santuario `xmlsec` 4.0.4 |
| **21.0.0** | 21 | Apache Santuario `xmlsec` 4.0.4 |

## Cryptography strength

Java 21 enables unlimited-strength JCE by default. `CertificateUtils.checkJCEpolicyIsUnlimited()` still fails fast if AES-256 or RSA (>= 1024-bit) is blocked.

## Building from source

See **CONTRIBUTING.md**.

## Local development

See **CONTRIBUTING.md** - Local builds section.

## License

Apache License 2.0 - see **LICENSE.txt**.

## Copyright

Copyright 2009 NEHTA. Copyright 2021-2026 ADHA. Apache License 2.0 - see **LICENSE.txt**.
