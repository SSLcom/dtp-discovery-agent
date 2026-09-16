Keystores produced by the reference implementation — OpenJDK 21's `keytool`,
run in `eclipse-temurin:21-jdk` — not by this repository.

That is the whole point of them. A fixture written by our own encoder would test
the parser against the same belief that wrote it, and a misreading of the format
would pass. These were made by the tool the format belongs to, and the tests
assert the SHA-256 fingerprints `keytool -list` itself printed for them.

| file | store password | contents |
|---|---|---|
| `real.jks` | `changeit` | `tomcat` (RSA PrivateKeyEntry), `other` (EC PrivateKeyEntry), `trustedroot` (trustedCertEntry) |
| `real.jceks` | `changeit` | `jceks-app` (RSA PrivateKeyEntry) |
| `truststore.jks` | `changeit` | two public CA roots, no end-entity certificate — the shape of a `cacerts` |

The passwords are irrelevant to what the agent does: certificate entries in a
JKS are not encrypted, so it never needs one and never asks for one.
