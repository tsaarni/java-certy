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

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateRevocationList {

    // Attributes set by user via builder methods.
    private Credential issuer;
    private List<Credential> revoked;
    private Date thisUpdate;
    private Date nextUpdate;

    /**
     * Creates new CRL builder.
     */
    public CertificateRevocationList() {
        revoked = new ArrayList<>();
    }

    /**
     * Defines the issue date of the CRL.
     *
     * @param val Time of the update of the CRL.
     * @return The CertificateRevocationList itself.
     */
    public CertificateRevocationList thisUpdate(Date val) {
        this.thisUpdate = val;
        return this;
    }

    /**
     * Defines the date when the next CRL will be issued.
     *
     * @param val Time of the next update of the CRL.
     * @return The CertificateRevocationList itself.
     */
    public CertificateRevocationList nextUpdate(Date val) {
        this.nextUpdate = val;
        return this;
    }

    /**
     * Defines the issuer of the CRL.
     * If the issuer is not set, the issuer of the revoked certificates is used.
     *
     * @param val Instance of {@link Credential} that will be used to sign the CRL.
     * @return The CertificateRevocationList itself.
     */
    public CertificateRevocationList issuer(Credential val) {
        this.issuer = val;
        return this;
    }

    /**
     * Adds a revoked certificate to the CRL.
     *
     * @param val Instance of {@link Credential} that will be revoked.
     * @return The CertificateRevocationList itself.
     */
    public CertificateRevocationList add(Credential val) {
        this.revoked.add(val);
        return this;
    }

    /**
     * Returns the CRL as DER.
     *
     * @return The CRL as DER.
     */
    public byte[] getAsDer() throws CertificateException, NoSuchAlgorithmException, IOException {
        return generateCrl().getEncoded();
    }

    /**
     * Returns the CRL as PEM.
     *
     * @return The CRL as PEM.
     */
    public String getAsPem() throws CertificateException, NoSuchAlgorithmException, IOException {
        StringWriter writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(generateCrl());
        pemWriter.flush();
        pemWriter.close();

        return writer.toString();
    }

    /**
     * Writes the CRL to a file as PEM block.
     *
     * @param out Path to the file.
     * @return The CertificateRevocationList itself.
     */
    public CertificateRevocationList writeAsPem(Path out) throws IOException, CertificateException, NoSuchAlgorithmException {

        try (BufferedWriter writer = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            writer.write(getAsPem());
        }

        return this;
    }

    // Generates the CRL.
    private X509CRLHolder generateCrl() throws CertificateException, NoSuchAlgorithmException {
        if (this.issuer == null) {
            if (this.revoked.isEmpty()) {
                throw new IllegalArgumentException("issuer not known: either set issuer or add certificates to the CRL");
            }
            this.issuer = this.revoked.get(0).issuer;
        }

        Date effectiveRevocationTime = new Date();
        if (this.thisUpdate != null) {
            effectiveRevocationTime = this.thisUpdate;
        }

        Duration week = Duration.ofDays(7);
        Date effectiveExpiry = Date.from(effectiveRevocationTime.toInstant().plus(week));
        if (this.nextUpdate != null) {
            effectiveExpiry = this.nextUpdate;
        }

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer.subject, effectiveRevocationTime);
        crlBuilder.setNextUpdate(effectiveExpiry);

        for (Credential credential : this.revoked) {
            credential.ensureGenerated();

            if (credential.issuer == null) {
                throw new IllegalArgumentException("cannot revoke self-signed certificate: " + credential.subject);
            } else if (!credential.issuer.equals(this.issuer)) {
                throw new IllegalArgumentException(
                        "revoked certificates added from several issuers, or certificate does not match explicitly set Issuer");
            }

            crlBuilder.addCRLEntry(credential.serial, effectiveRevocationTime, 0, effectiveExpiry);
        }

        X509CRLHolder crlHolder;
        try {
            ContentSigner signer = new JcaContentSignerBuilder(
                    Credential.signatureAlgorithm(issuer.keyPair.getPublic())).build(issuer.keyPair.getPrivate());
            crlHolder = crlBuilder.build(signer);
        } catch (OperatorCreationException e) {
            throw new CertificateException("failed to create content signer", e);
        }

        return crlHolder;
    }

}
