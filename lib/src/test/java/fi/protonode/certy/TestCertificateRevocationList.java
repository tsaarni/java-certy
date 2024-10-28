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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.StringReader;
import java.nio.file.Path;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

public class TestCertificateRevocationList {

    private static CertificateFactory cf;
    private static Credential ca;
    private static Credential revokedCert;
    private static Credential notRevokedCert;

    @BeforeAll
    public static void init() throws Exception {
        cf = CertificateFactory.getInstance("X.509");

        ca = new Credential().subject("CN=ca");
        revokedCert = new Credential().issuer(ca).subject("CN=revoked");
        notRevokedCert = new Credential().issuer(ca).subject("CN=not-revoked");
    }

    @Test
    void testAdd() throws Exception {
        Credential anotherRevokedCert = new Credential().issuer(ca).subject("CN=revoked");
        CertificateRevocationList crl = new CertificateRevocationList().add(revokedCert).add(anotherRevokedCert);
        assertNotNull(crl);

        CRL got = cf.generateCRL(new ByteArrayInputStream(crl.getAsDer()));
        assertNotNull(got);
        assertTrue(got.isRevoked(revokedCert.getCertificate()));
        assertTrue(got.isRevoked(anotherRevokedCert.getCertificate()));
        assertFalse(got.isRevoked(notRevokedCert.getCertificate()));
    }

    @Test
    void testThisUpdate() throws Exception {
        Date thisUpdate = Date.from(Instant.parse("2023-01-01T09:00:00Z"));
        CertificateRevocationList crl = new CertificateRevocationList().thisUpdate(thisUpdate).add(revokedCert);
        assertNotNull(crl);

        CRL got = cf.generateCRL(new ByteArrayInputStream(crl.getAsDer()));
        assertNotNull(got);
        assertEquals(thisUpdate, ((X509CRL) got).getThisUpdate());
    }

    @Test
    void testNextUpdate() throws Exception {
        Date nextUpdate = Date.from(Instant.parse("2100-01-01T09:00:00Z"));
        CertificateRevocationList crl = new CertificateRevocationList().nextUpdate(nextUpdate).add(revokedCert);
        assertNotNull(crl);

        CRL got = cf.generateCRL(new ByteArrayInputStream(crl.getAsDer()));
        assertNotNull(got);
        assertEquals(nextUpdate, ((X509CRL) got).getNextUpdate());
    }

    @Test
    void testIssuer() throws Exception {
        CertificateRevocationList crl = new CertificateRevocationList().issuer(ca).add(revokedCert);
        assertNotNull(crl);

        CRL got = cf.generateCRL(new ByteArrayInputStream(crl.getAsDer()));
        assertNotNull(got);
        assertEquals(((X509Certificate) ca.getCertificate()).getSubjectX500Principal(),
                ((X509CRL) got).getIssuerX500Principal());
    }

    @Test
    void testGetPem() throws Exception {
        CertificateRevocationList crl = new CertificateRevocationList().add(revokedCert);
        assertNotNull(crl);

        String pem = crl.getAsPem();
        assertNotNull(pem);

        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            PemObject obj = parser.readPemObject();
            assertEquals("X509 CRL", obj.getType());
            CRL got = cf.generateCRL(new ByteArrayInputStream(obj.getContent()));
            assertNotNull(got);
            assertTrue(got.isRevoked(revokedCert.getCertificate()));
        }
    }

    @Test
    void testWritingPem(@TempDir Path tempDir) throws Exception {
        Path crlPath = tempDir.resolve("crl.pem");

        CertificateRevocationList crl = new CertificateRevocationList().add(revokedCert).writeAsPem(crlPath);
        assertNotNull(crl);

        CRL got = cf.generateCRL(new FileInputStream(crlPath.toFile()));
        assertNotNull(got);
        assertTrue(got.isRevoked(revokedCert.getCertificate()));
        assertFalse(got.isRevoked(notRevokedCert.getCertificate()));
    }

    @Test
    void testUninitializedCaCertificate(@TempDir Path tempDir) {
        Credential uninitialized = new Credential().subject("cn=ca"); // We have not called generate() yet.
        assertDoesNotThrow(() -> new CertificateRevocationList().issuer(uninitialized).writeAsPem(tempDir.resolve("crl.pem")));
    }

    @Test
    void testUninitializedRevokedCertificate(@TempDir Path tempDir) {
        Credential uninitialized = new Credential().issuer(ca).subject("cn=uninitialized");  // We have not called generate() yet.
        assertDoesNotThrow(() -> new CertificateRevocationList().issuer(ca).add(uninitialized).writeAsPem(tempDir.resolve("crl.pem")));
    }

}
