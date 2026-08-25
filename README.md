# smi-xsp - XML Secured Payload Profiles

Java implementation of XML Secured Payload Profiles for the Australian Digital Health Agency.

## Dependency (Maven Central)

```xml
<dependency>
    <groupId>au.gov.nehta</groupId>
    <artifactId>smi-xsp</artifactId>
    <version>8.0.0</version>
</dependency>
```

## Runtime requirements

- Java 8 or later
- Apache Santuario (`xmlsec`) is a transitive dependency and is included automatically

## JCE Unlimited Strength

For JDK 8 versions earlier than 8u161, install the JCE Unlimited Strength Jurisdiction Policy files
from Oracle to enable full cryptographic strength. JDK 8u161+ and all later JDKs enable unlimited
strength by default.

## Building from source

See **CONTRIBUTING.md**.

## Local development

See **CONTRIBUTING.md** - Local builds section.

## License

Apache License 2.0 - see **LICENSE.txt**.

## Copyright

Copyright 2009 NEHTA. Copyright 2021-2026 ADHA. Apache License 2.0 - see **LICENSE.txt**.
