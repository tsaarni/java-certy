# Certy

![](https://github.com/tsaarni/certy/workflows/unit-tests/badge.svg)

## Description

Certy gives you a simple Java API to create X509 certificates for your unit tests.
No more committing test certificates and keys into the repository!

Certy is Java version of similar tool for command line and Golang use: [certyaml](https://github.com/tsaarni/certyaml).

## Example

Two credentials are created: `ca` and `server`.
The `ca` certificate will be created with defaults parameters: it will be self-signed certificate with 256 bits EC key type.
The `server` certificate is set to be signed by the `ca` and its subject alternative name is set to `www.example.com`.

```java
Credential ca = new Credential().subject("CN=ca");
Credential server = new Credential().subject("CN=server")
                                    .issuer(ca)
                                    .subjectAltName("DNS:www.example.com");
```

Next, we can write CA certificate, server certificate and key to disk in PEM format:

```java
ca.writeCertificateAsPem(Paths.get("ca.pem"));
server.writeCertificateAsPem(Paths.get("server.pem"))
      .writePrivateKeyAsPem(Paths.get("server-key.pem"));
```

Or alternatively, we can create truststore and keystore in PKCS12 format:

```java
KeyStore truststore = KeyStore.getInstance("PKCS12");
truststore.load(null, null);
truststore.setCertificateEntry("ca", ca.getCertificate());
truststore.store(Files.newOutputStream(Paths.get("trusted.p12")), "secret".toCharArray());

KeyStore keystore = KeyStore.getInstance("PKCS12");
keystore.load(null, null);
keystore.setKeyEntry("server", server.getPrivateKey(), null, server.getCertificates());
keystore.store(Files.newOutputStream(Paths.get("server.p12")), "secret".toCharArray());
```
