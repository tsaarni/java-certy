# Certy

![](https://github.com/tsaarni/certy/workflows/unit-tests/badge.svg)

## Description

Certy gives you a simple Java API for creating X509 certificates inside your unit tests.
No more committing test certificates and keys into the repository!

Certy is Java version of similar tool for command line and Golang: [certyaml](https://github.com/tsaarni/certyaml).

## Documentation

Read the latest documentation [here](https://tsaarni.github.io/certy/).

## Example

Two credentials are created: `ca` and `server`.
The defaults work for most use cases so only minimal set of fields needs to be defined.
For example `ca` certificate will be self-signed root CA certificate since issuer is not set.
The `server` certificate is set to be signed by the `ca` and its subject alternative name is set to `app.127.0.0.1.nip.io` to allow its use as server certificate for given FQDN.

```java
Credential ca = new Credential().subject("CN=ca");
Credential server = new Credential().subject("CN=server")
                                    .issuer(ca)
                                    .subjectAltName("DNS:app.127.0.0.1.nip.io");
```

The `ca` certificate, `server` certificate and associated private key are written to the disk in PEM format:

```java
ca.writeCertificateAsPem(Paths.get("ca.pem"));
server.writeCertificateAsPem(Paths.get("server.pem"))
      .writePrivateKeyAsPem(Paths.get("server-key.pem"));
```

Or they can be stored in PKCS12 truststore and keystore:

```java
KeyStore truststore = KeyStore.getInstance("PKCS12");
truststore.load(null, null); // Required to initialize the keystore.
truststore.setCertificateEntry("ca", ca.getCertificate());
truststore.store(Files.newOutputStream(Paths.get("trusted.p12")), "secret".toCharArray());

KeyStore keystore = KeyStore.getInstance("PKCS12");
keystore.load(null, null);
keystore.setKeyEntry("server", server.getPrivateKey(), null, server.getCertificates());
keystore.store(Files.newOutputStream(Paths.get("server.p12")), "secret".toCharArray());
```
