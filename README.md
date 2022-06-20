# Certy

![](https://github.com/tsaarni/java-certy/workflows/unit-tests/badge.svg)

## Description

Certy is a simple to use Java API for creating X509 certificates on demand when running unit tests.
No more storing test certificates and private keys in the repository!

Certy is Java version of similar tool for command line and Golang: [certyaml](https://github.com/tsaarni/certyaml).

## Documentation

Read the latest documentation [here](https://tsaarni.github.io/java-certy/).

## Example

Two credentials are created: `ca` and `server`.
Only minimal set of fields needs to be defined since defaults work for most use cases.
For example `ca` certificate will be self-signed root CA since issuer is not set.
The `server` certificate is set to be signed by `ca` and its subject alternative name is set to `app.127.0.0.1.nip.io` to allow its use as server certificate for given domain.
Key usage for end-entity certificates defaults to allow their use as both server and client certificates.
When the defaults are not correct for particular use, they can be overwritten by calling the [builder methods](https://tsaarni.github.io/java-certy/fi/protonode/certy/Credential.html#method-summary).

```java
Credential ca = new Credential().subject("CN=ca");
Credential server = new Credential().subject("CN=server")
                                    .issuer(ca)
                                    .subjectAltName("DNS:app.127.0.0.1.nip.io");
```

The `ca` certificate, `server` certificate and associated private key are written as PEM files:

```java
ca.writeCertificateAsPem(Paths.get("ca.pem"));
server.writeCertificateAsPem(Paths.get("server.pem"))
      .writePrivateKeyAsPem(Paths.get("server-key.pem"));
```

They can be stored in PKCS12 (or JKS) truststore and keystore:

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

Following certificates were created:

```console
$ openssl x509 -in ca.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1655536454193 (0x18175a98a31)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = ca
        Validity
            Not Before: Jun 18 07:14:14 2022 GMT
            Not After : Jun 18 07:14:14 2023 GMT
        Subject: CN = ca
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    ...
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                8F:14:88:5A:27:5D:F5:B8:8D:16:AB:F1:51:21:29:F8:52:5A:65:0B
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
    Signature Algorithm: ecdsa-with-SHA256
         ...

$ openssl x509 -in server.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1655536454415 (0x18175a98b0f)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = ca
        Validity
            Not Before: Jun 18 07:14:14 2022 GMT
            Not After : Jun 18 07:14:14 2023 GMT
        Subject: CN = server
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    ...
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                B0:AC:25:D9:8D:5D:17:02:22:DA:71:C0:52:04:D3:8E:B4:A0:AC:D9
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Key Agreement
            X509v3 Subject Alternative Name:
                DNS:app.127.0.0.1.nip.io
    Signature Algorithm: ecdsa-with-SHA256
         ...
```

And the content of keystores:

```console
$ keytool -list  -keystore trusted.p12 -storepass secret
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

ca, Jun 18, 2022, trustedCertEntry,
Certificate fingerprint (SHA-256): 3F:54:0D:F3:CE:A8:0A:E9:72:D1:55:96:2B:A2:4E:11:5E:96...

$ keytool -list -keystore server.p12 -storepass secret
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

server, Jun 18, 2022, PrivateKeyEntry,
Certificate fingerprint (SHA-256): 4E:6A:7C:57:B7:21:31:E2:58:6E:35:95:5F:26:4F:8F:F9:F4...
```

Check out the [unit tests](lib/src/test/java/fi/protonode/certy/TestCredential.java) for more code examples.
