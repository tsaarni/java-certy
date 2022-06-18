/*
 * Copyright Certy Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fi.protonode.certy;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import fi.protonode.certy.Credential.ExtKeyUsage;
import fi.protonode.certy.Credential.KeyType;
import fi.protonode.certy.Credential.KeyUsage;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;

public class TestCredential {

    @Test
    void testSubjectName() throws Exception {
        X509Certificate cert = new Credential().subject("CN=joe").getX509Certificate();
        assertNotNull(cert);
        assertEquals("CN=joe", cert.getSubjectX500Principal().getName());
    }

    @Test
    void testSubjectAltName() throws Exception {
        X509Certificate cert = new Credential().subject("CN=joe")
                .subjectAltNames(Arrays.asList("DNS:host.example.com", "URI:http://www.example.com", "IP:1.2.3.4"))
                .getX509Certificate();
        assertNotNull(cert);
        assertEquals("CN=joe", cert.getSubjectX500Principal().getName());
        Object expected[] = new Object[] {
                Arrays.asList(GeneralName.dNSName, "host.example.com"),
                Arrays.asList(GeneralName.uniformResourceIdentifier, "http://www.example.com"),
                Arrays.asList(GeneralName.iPAddress, "1.2.3.4") };
        assertArrayEquals(expected, cert.getSubjectAlternativeNames().toArray());
    }

    @Test
    void testDefaultKeySizes() throws Exception {
        Credential credEc = new Credential().subject("CN=joe");
        expectKey(credEc.getX509Certificate(), "EC", 256);
        Credential credRsa = new Credential().keyType(KeyType.RSA).subject("CN=joe");
        expectKey(credRsa.getX509Certificate(), "RSA", 2048);
    }

    @Test
    void testEcKeySizes() throws Exception {
        Credential cred = new Credential().subject("CN=joe")
                .keyType(KeyType.EC)
                .keySize(256);
        expectKey(cred.getX509Certificate(), "EC", 256);
        cred.keySize(384).generate();
        expectKey(cred.getX509Certificate(), "EC", 384);
        cred.keySize(521).generate();
        expectKey(cred.getX509Certificate(), "EC", 521);
    }

    @Test
    void testRsaKeySizes() throws Exception {
        Credential cred = new Credential().subject("CN=joe")
                .keyType(KeyType.RSA)
                .keySize(1024);
        expectKey(cred.getX509Certificate(), "RSA", 1024);
        cred.keySize(2048).generate();
        expectKey(cred.getX509Certificate(), "RSA", 2048);
        cred.keySize(4096).generate();
        expectKey(cred.getX509Certificate(), "RSA", 4096);
    }

    @Test
    void testExpires() throws Exception {
        Duration hour = Duration.of(1, ChronoUnit.HOURS);
        X509Certificate cert = new Credential().subject("CN=joe").expires(hour).getX509Certificate();
        assertNotNull(cert);
        assertEquals(hour, Duration.between(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant()));
    }

    @Test
    void testKeyUsage() throws Exception {
        Credential cred = new Credential().subject("CN=joe");

        // Order of the boolean array from:
        //    boolean[] java.security.cert.X509Certificate.getKeyUsage()
        //
        //  digitalSignature        (0),
        //  nonRepudiation          (1),
        //  keyEncipherment         (2),
        //  dataEncipherment        (3),
        //  keyAgreement            (4),
        //  keyCertSign             (5),
        //  cRLSign                 (6),
        //  encipherOnly            (7),
        //  decipherOnly            (8)
        assertArrayEquals(new boolean[] { true, false, false, false, false, false, false, false, false },
                cred.keyUsages(Arrays.asList(KeyUsage.DIGITAL_SIGNATURE)).getX509Certificate().getKeyUsage());

        assertArrayEquals(new boolean[] { true, false, true, false, false, false, false, false, false },
                cred.keyUsages(Arrays.asList(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT))
                        .generate()
                        .getX509Certificate().getKeyUsage());

        assertArrayEquals(new boolean[] { true, true, true, true, true, true, true, true, true },
                cred.keyUsages(Arrays.asList(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION,
                        KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DATA_ENCIPHERMENT, KeyUsage.KEY_AGREEMENT,
                        KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN, KeyUsage.ENCIPHER_ONLY, KeyUsage.DECIPHER_ONLY))
                        .generate()
                        .getX509Certificate().getKeyUsage());
    }

    @Test
    void testExtendedKeyUsage() throws Exception {
        Credential cred = new Credential().subject("CN=joe");

        assertEquals(Arrays.asList(KeyPurposeId.anyExtendedKeyUsage.toString()),
                cred.extKeyUsages(Arrays.asList(ExtKeyUsage.ANY)).getX509Certificate().getExtendedKeyUsage());

        assertEquals(Arrays.asList(KeyPurposeId.id_kp_clientAuth.toString(), KeyPurposeId.id_kp_serverAuth.toString()),
                cred.extKeyUsages(Arrays.asList(ExtKeyUsage.CLIENT_AUTH, ExtKeyUsage.SERVER_AUTH))
                        .generate()
                        .getX509Certificate().getExtendedKeyUsage());

        assertEquals(
                Arrays.asList(KeyPurposeId.id_kp_clientAuth.toString(), KeyPurposeId.id_kp_serverAuth.toString(),
                        KeyPurposeId.id_kp_codeSigning.toString(), KeyPurposeId.id_kp_emailProtection.toString(),
                        KeyPurposeId.id_kp_OCSPSigning.toString(), KeyPurposeId.id_kp_timeStamping.toString()),
                cred.extKeyUsages(
                        Arrays.asList(ExtKeyUsage.CLIENT_AUTH, ExtKeyUsage.SERVER_AUTH, ExtKeyUsage.CODE_SIGNING,
                                ExtKeyUsage.EMAIL_PROTECTION, ExtKeyUsage.OCSP_SIGNING, ExtKeyUsage.TIME_STAMPING))
                        .generate()
                        .getX509Certificate().getExtendedKeyUsage());
    }

    @Test
    void testIssuer() throws Exception {
        Credential issuer = new Credential().subject("CN=ca");
        assertEquals("CN=ca", issuer.getX509Certificate().getSubjectX500Principal().toString());
        assertEquals("CN=ca", issuer.getX509Certificate().getIssuerX500Principal().toString());
        assertEquals(Integer.MAX_VALUE, issuer.getX509Certificate().getBasicConstraints()); // CA:true

        Credential endEntity = new Credential().subject("CN=end-entity").issuer(issuer);
        assertEquals("CN=end-entity", endEntity.getX509Certificate().getSubjectX500Principal().toString());
        assertEquals("CN=ca", endEntity.getX509Certificate().getIssuerX500Principal().toString());
        assertEquals(-1, endEntity.getX509Certificate().getBasicConstraints()); // CA:false
    }

    @Test
    void testIsCa() throws Exception {
        Credential issuer = new Credential().subject("CN=joe");
        assertArrayEquals(new boolean[] { false, false, false, false, false, true, true, false, false },
                issuer.getX509Certificate().getKeyUsage());
        assertEquals(Integer.MAX_VALUE, issuer.getX509Certificate().getBasicConstraints()); // CA:true

        issuer.isCa(true).generate();
        assertArrayEquals(new boolean[] { false, false, false, false, false, true, true, false, false },
                issuer.getX509Certificate().getKeyUsage());
        assertEquals(Integer.MAX_VALUE, issuer.getX509Certificate().getBasicConstraints()); // CA:true

        Credential endEntity = new Credential().subject("CN=end-entity").issuer(issuer);
        assertArrayEquals(new boolean[] { true, false, true, false, true, false, false, false, false },
                endEntity.getX509Certificate().getKeyUsage());
        assertEquals(-1, endEntity.getX509Certificate().getBasicConstraints()); // CA:false
    }

    @Test
    void testNotBeforeAndNotAfter() throws Exception {
        Date wantNotBefore = Date.from(Instant.parse("2022-01-01T09:00:00Z"));
        Date wantNotAfter = Date.from(Instant.parse("2022-02-01T09:00:00Z"));
        Duration defaultDuration = Duration.of(365, ChronoUnit.DAYS);

        X509Certificate cert1 = new Credential().subject("CN=joe").notBefore(wantNotBefore).getX509Certificate();
        assertNotNull(cert1);
        assertEquals(wantNotBefore, cert1.getNotBefore());
        assertEquals(Date.from(wantNotBefore.toInstant().plus(defaultDuration)), cert1.getNotAfter());

        X509Certificate cert2 = new Credential().subject("CN=joe").notBefore(wantNotBefore).notAfter(wantNotAfter)
                .getX509Certificate();
        assertNotNull(cert2);
        assertEquals(wantNotBefore, cert2.getNotBefore());
        assertEquals(wantNotAfter, cert2.getNotAfter());
    }

    @Test
    void testInvalidSubject() throws Exception {
        Credential cred = new Credential();
        assertThrows(IllegalArgumentException.class, () -> cred.subject("Foo=Bar"));
    }

    @Test
    void testEmptySubjectAndSubjectAltNames() throws Exception {
        // Both subject and subject alternative name cannot be empty.
        Credential cred = new Credential();
        assertThrows(IllegalArgumentException.class, () -> cred.getX509Certificate());
    }

    @Test
    void testInvalidSubjectAltName() throws Exception {
        Credential cred = new Credential().subject("CN=joe");
        assertThrows(IllegalArgumentException.class, () -> cred.subjectAltName("EMAIL:user@example.com"));
        assertThrows(IllegalArgumentException.class, () -> cred.subjectAltName("URL:"));
        assertThrows(IllegalArgumentException.class, () -> cred.subjectAltName("IP:999.999.999.999"));
        assertThrows(IllegalArgumentException.class, () -> cred.subjectAltName("does-not-parse"));
    }

    @Test
    void testInvalidKeySize() throws Exception {
        Credential cred1 = new Credential().subject("CN=joe").keyType(KeyType.EC).keySize(1);
        assertThrows(IllegalArgumentException.class, () -> cred1.getX509Certificate());

        Credential cred2 = new Credential().subject("CN=joe").keyType(KeyType.RSA).keySize(1);
        assertThrows(IllegalArgumentException.class, () -> cred2.getX509Certificate());
    }

    @Test
    void testGettingPemsAsStrings() throws Exception {
        Credential ca = new Credential().subject("CN=ca");
        Credential server = new Credential().subject("CN=server").issuer(ca).subjectAltName("DNS:localhost");
        Credential client = new Credential().subject("CN=client").keyType(KeyType.RSA).issuer(ca);

        expectPemCertificate(new BufferedReader(new StringReader(ca.getCertificateAsPem())), "CN=ca");
        expectPemPrivateKey(new BufferedReader(new StringReader(ca.getPrivateKeyAsPem())), "EC");

        expectPemCertificate(new BufferedReader(new StringReader(server.getCertificateAsPem())), "CN=server");
        expectPemPrivateKey(new BufferedReader(new StringReader(server.getPrivateKeyAsPem())), "EC");

        expectPemCertificate(new BufferedReader(new StringReader(client.getCertificateAsPem())), "CN=client");
        expectPemPrivateKey(new BufferedReader(new StringReader(client.getPrivateKeyAsPem())), "RSA");
    }

    @Test
    void testWritingPemFiles(@TempDir Path tempDir) throws Exception {
        Path certPath = tempDir.resolve("joe.pem");
        Path keyPath = tempDir.resolve("joe-key.pem");

        new Credential().subject("CN=joe").writeCertificateAsPem(certPath).writePrivateKeyAsPem(keyPath);
        expectPemCertificate(Files.newBufferedReader(certPath), "CN=joe");
        expectPemPrivateKey(Files.newBufferedReader(keyPath), "EC");
    }

    @Test
    void testCreateInMemoryPkcs12KeyStore() throws Exception {
        Credential ca = new Credential().subject("CN=ca");
        Credential client = new Credential().subject("CN=client").issuer(ca);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", client.getPrivateKey(), null, client.getCertificates());
        ks.setCertificateEntry("ca", ca.getCertificate());
        assertEquals(2, ks.size());
        assertEquals(ca.getCertificate(), ks.getCertificate("ca"));
        assertEquals(client.getCertificate(), ks.getCertificate("client"));
    }

    @Test
    void testIntermediateCa() throws Exception {
        Credential ca = new Credential().subject("CN=ca");
        assertEquals("CN=ca", ca.getX509Certificate().getSubjectX500Principal().toString());
        assertEquals("CN=ca", ca.getX509Certificate().getIssuerX500Principal().toString());
        assertEquals(Integer.MAX_VALUE, ca.getX509Certificate().getBasicConstraints()); // CA:true

        Credential subCa = new Credential().subject("CN=sub-ca").issuer(ca).isCa(true);
        assertEquals("CN=sub-ca", subCa.getX509Certificate().getSubjectX500Principal().toString());
        assertEquals("CN=ca", subCa.getX509Certificate().getIssuerX500Principal().toString());
        assertEquals(Integer.MAX_VALUE, subCa.getX509Certificate().getBasicConstraints()); // CA:true

        Credential endEntity = new Credential().subject("CN=end-entity").issuer(subCa);
        assertEquals("CN=end-entity", endEntity.getX509Certificate().getSubjectX500Principal().toString());
        assertEquals("CN=sub-ca", endEntity.getX509Certificate().getIssuerX500Principal().toString());
        assertEquals(-1, endEntity.getX509Certificate().getBasicConstraints()); // CA:false
    }

    @Test
    void testSerialNumber() throws Exception {
        BigInteger serial = BigInteger.valueOf(1234);
        X509Certificate cert = new Credential().subject("CN=joe").serial(serial).getX509Certificate();
        assertEquals(serial, cert.getSerialNumber());

        // Serial number should have unique value, even if not set explicitly.
        X509Certificate certNoExplicitSerial1 = new Credential().subject("CN=joe").getX509Certificate();
        X509Certificate certNoExplicitSerial2 = new Credential().subject("CN=jen").getX509Certificate();
        assertNotEquals(BigInteger.valueOf(0), certNoExplicitSerial1.getSerialNumber());
        assertNotEquals(BigInteger.valueOf(0), certNoExplicitSerial2.getSerialNumber());
        assertNotEquals(certNoExplicitSerial1.getSerialNumber(), certNoExplicitSerial2.getSerialNumber());
    }


    // Helper methods.

    // Check expected key type and size.
    void expectKey(X509Certificate cert, String expectedKeyType, int expectedSize) {
        assertNotNull(cert);
        switch (expectedKeyType) {
            case "EC":
                assertEquals("EC", cert.getPublicKey().getAlgorithm());
                ECPublicKey ecKey = (ECPublicKey) cert.getPublicKey();
                ECParameterSpec spec = ecKey.getParams();
                assertEquals(expectedSize, spec.getOrder().bitLength());
                break;
            case "RSA":
                assertEquals("RSA", cert.getPublicKey().getAlgorithm());
                RSAPublicKey rsaKey = (RSAPublicKey) cert.getPublicKey();
                assertEquals(expectedSize, rsaKey.getModulus().bitLength());
                break;
            default:
                fail("invalid key type given to test case");
        }
    }

    // Check if reader yields certificate in PEM format and it has given subject name.
    void expectPemCertificate(BufferedReader reader, String expectedDn) throws CertificateException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        PEMParser parser = new PEMParser(reader);
        PemObject obj = parser.readPemObject();
        parser.close();
        assertEquals("CERTIFICATE", obj.getType());
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(obj.getContent()));
        assertEquals(expectedDn, cert.getSubjectX500Principal().toString());
    }

    // Check if reader yields private key in PEM format and it is of given type.
    void expectPemPrivateKey(BufferedReader reader, String expectedKeyType)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        PEMParser parser = new PEMParser(reader);
        PemObject obj = parser.readPemObject();
        parser.close();
        assertEquals("PRIVATE KEY", obj.getType());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(obj.getContent());
        // Will throw if key is not right type.
        KeyFactory.getInstance(expectedKeyType).generatePrivate(spec);
    }
}
