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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Credential {

    /** Key type values fo {@link #keyType()}. */
    public enum KeyType {
        EC,
        RSA
    }

    /** Key usage values for {@link #keyUsages()}. */
    public enum KeyUsage {
        DIGITAL_SIGNATURE(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature),
        NON_REPUDIATION(org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation),
        KEY_ENCIPHERMENT(org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment),
        DATA_ENCIPHERMENT(org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment),
        KEY_AGREEMENT(org.bouncycastle.asn1.x509.KeyUsage.keyAgreement),
        KEY_CERT_SIGN(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign),
        CRL_SIGN(org.bouncycastle.asn1.x509.KeyUsage.cRLSign),
        ENCIPHER_ONLY(org.bouncycastle.asn1.x509.KeyUsage.encipherOnly),
        DECIPHER_ONLY(org.bouncycastle.asn1.x509.KeyUsage.decipherOnly);

        private int val;

        private KeyUsage(int val) {
            this.val = val;
        }

        public int getValue() {
            return val;
        }
    }

    /** Extended key usage values for {@link #extKeyUsages()}. */
    public enum ExtKeyUsage {
        ANY(KeyPurposeId.anyExtendedKeyUsage),
        SERVER_AUTH(KeyPurposeId.id_kp_serverAuth),
        CLIENT_AUTH(KeyPurposeId.id_kp_clientAuth),
        CODE_SIGNING(KeyPurposeId.id_kp_codeSigning),
        EMAIL_PROTECTION(KeyPurposeId.id_kp_emailProtection),
        TIME_STAMPING(KeyPurposeId.id_kp_timeStamping),
        OCSP_SIGNING(KeyPurposeId.id_kp_OCSPSigning);

        private KeyPurposeId val;

        private ExtKeyUsage(KeyPurposeId val) {
            this.val = val;
        }

        public KeyPurposeId getValue() {
            return val;
        }
    }

    // Attributes set by user via builder methods.
    private X500Name subject;
    private GeneralNames subjectAltNames;
    private KeyType keyType;
    private int keySize;
    private Duration expires;
    private Date notBefore;
    private Date notAfter;
    private List<KeyUsage> keyUsages;
    private List<ExtKeyUsage> extKeyUsages;
    private Credential issuer;
    private Boolean isCa;

    // Generated attributes.
    private KeyPair keyPair;
    private Certificate certificate;

    public Credential() {
        keyUsages = new ArrayList<>();
        extKeyUsages = new ArrayList<>();
        // Defaults will be set after builder methods, when generate() is called.
    }

    /**
     * Defines the distinguished name for the certificate.<p>
     * Example: {@code "CN=Joe"}.
     *
     * @param val Subject name.
     */
    public Credential subject(String val) {
        this.subject = new X500Name(val);
        return this;
    }

    /**
     * Defines an optional list of values for x509 Subject Alternative Name extension.<p>
     * Examples: {@code "DNS:www.example.com"</code>},
     *           {@code "IP:1.2.3.4"},
     *           {@code "URI:https://www.example.com"}.
     * @param val List of subject alternative names.<p>
     */
    public Credential subjectAltNames(List<String> val) {
        this.subjectAltNames = asGeneralNames(val);
        return this;
    }

    /**
     * Defines an optional value for x509 Subject Alternative Name extension.<p>
     * Examples: {@code "DNS:www.example.com"</code>},
     *           {@code "IP:1.2.3.4"},
     *           {@code "URI:https://www.example.com"}.
     *
     * @param val Subject alternative name.
     */
    public Credential subjectAltName(String val) {
        this.subjectAltNames = asGeneralNames(Arrays.asList(val));
        return this;
    }

    /**
     * Defines the certificate key algorithm.
     * Defaults to {@code KeyType.EC} if not set.
     *
     * @param val Key type.
     */
    public Credential keyType(KeyType val) {
        this.keyType = val;
        return this;
    }

    /**
     * Defines the key length in bits.
     * Default value is 256 (EC) or 2048 (RSA) if keySize is not set.<p>
     * Examples: For keyType EC: 256, 384, 521.
     *           For keyType RSA: 1024, 2048, 4096.
     *
     * @param val Key size.
     */
    public Credential keySize(int val) {
        this.keySize = val;
        return this;
    }

    /**
     * Automatically defines certificate's NotAfter field by adding duration defined in Expires to the current time.
     * {@link #notAfter()} takes precedence over expires.
     * The default value is 1 year if not defined
     *
     * @param val Time until expiration.
     */
    public Credential expires(Duration val) {
        this.expires = val;
        return this;
    }

    /**
     * Defines certificate not to be valid before this time.
     * The default value is current time if not defined.
     *
     * @param val Date when certificate becomes valid.
     */
    public Credential notBefore(Date val) {
        this.notBefore = val;
        return this;
    }

    /**
     * Defines certificate not to be valid after this time.
     * Default value is current time + expires if {@code notAfter} is not defined.
     *
     * @param val Date when certificate expires.
     */
    public Credential notAfter(Date val) {
        this.notAfter = val;
        return this;
    }

    /**
     * Defines a sequence of values for x509 key usage extension.<p>
     *
     * If {@code keyUsage} is undefined following defaults are used:<p>
     * CertSign and CRLSign are set for CA certificates.
     * KeyEncipherment and DigitalSignature are set for end-entity certificates with RSA key.
     * KeyEncipherment, DigitalSignature and KeyAgreement are set for end-entity certificates with EC key.
     *
     * @param val List of key usages.
     */
    public Credential keyUsages(List<KeyUsage> val) {
        this.keyUsages = val;
        return this;
    }

    /**
     * Defines a sequence of x509 extended key usages.
     * Not defined by default.
     *
     * @param val List of extended key usages.
     */
    public Credential extKeyUsages(List<ExtKeyUsage> val) {
        this.extKeyUsages = val;
        return this;
    }

    /**
     * Defines the issuer Certificate.
     * Self-signed certificate is generated if issuer is not defined.
     *
     * @param val Instance of {@code Credential} that will be used to sign this certificate.
     */
    public Credential issuer(Credential val) {
        this.issuer = val;
        return this;
    }

    /**
     * Defines certificate's basic constraints isCA attribute.
     * If IsCA is not defined, self-signed certificates are set as CA certificates, everything else is not set.
     *
     * @param val Value for isCA attribute of basic constraints.
     */
    public Credential isCa(Boolean val) {
        this.isCa = val;
        return this;
    }

    /**
     * (Re)generate certificate and private key with currently defined attributes.
     */
    public Credential generate()
            throws CertificateException, NoSuchAlgorithmException, CertIOException {
        // Traverse the certificate hierarchy recursively to ensure issuing CAs have
        // been generated as well.
        if (issuer != null) {
            issuer.ensureGenerated();
        }

        setDefaults();

        keyPair = newKeyPair(keyType, keySize);

        // Calculate the validity dates according to given values and current time.
        Date effectiveNotBefore;
        Date effectiveNotAfter;
        if (notBefore != null) {
            effectiveNotBefore = notBefore;
        } else {
            effectiveNotBefore = new Date(); // Now.
        }

        if (notAfter != null) {
            effectiveNotAfter = notAfter;
        } else {
            effectiveNotAfter = Date.from(effectiveNotBefore.toInstant().plus(expires));
        }

        if (subject == null) {
            throw new IllegalArgumentException("subject name must be set");
        }

        X500Name effectiveIssuer;
        ContentSigner signer;
        try {
            if (issuer == null) {
                effectiveIssuer = subject;
                    signer = new JcaContentSignerBuilder(signatureAlgorithm(keyPair.getPublic()))
                            .build(keyPair.getPrivate());
            } else {
                effectiveIssuer = issuer.subject;
                signer = new JcaContentSignerBuilder(signatureAlgorithm(issuer.keyPair.getPublic()))
                        .build(issuer.keyPair.getPrivate());
            }
        } catch (OperatorCreationException e) {
            throw new CertificateException(e.toString());
        }

        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                effectiveIssuer,
                BigInteger.valueOf(now.toEpochMilli()), // Current time as serial number.
                effectiveNotBefore,
                effectiveNotAfter,
                subject,
                keyPair.getPublic());

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa))
                .addExtension(Extension.subjectKeyIdentifier, false,
                        utils.createSubjectKeyIdentifier(keyPair.getPublic()))
                .addExtension(Extension.keyUsage, true, new org.bouncycastle.asn1.x509.KeyUsage(
                        keyUsages.stream().collect(Collectors.summingInt(KeyUsage::getValue))));

        if (subjectAltNames != null) {
            builder.addExtension(Extension.subjectAlternativeName, subject == null, subjectAltNames);
        }

        if (!extKeyUsages.isEmpty()) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
                    extKeyUsages.stream().map(ExtKeyUsage::getValue).toArray(KeyPurposeId[]::new)));
        }

        certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(builder.build(signer));

        return this;
    }

    /**
     * Returns PEM block containing the X509 certificate.
     *
     * @return String containing the certificate.
     */
    public String getCertificateAsPem() throws CertificateException, NoSuchAlgorithmException, IOException {
        ensureGenerated();

        StringWriter writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(certificate);
        pemWriter.flush();
        pemWriter.close();

        return writer.toString();
    }

    /**
     * Returns PEM block containing the private key in PKCS8 format.
     *
     * @return String containing the private key.
     */
    public String getPrivateKeyAsPem()
            throws IOException, CertificateException, NoSuchAlgorithmException {
        ensureGenerated();

        StringWriter writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(new JcaPKCS8Generator(keyPair.getPrivate(), null));
        pemWriter.flush();
        pemWriter.close();

        return writer.toString();
    }

    /**
     * Writes X509 certificate to a file as PEM.
     *
     * @param Path to write the PEM file to.
     */
    public Credential writeCertificateAsPem(Path out)
            throws IOException, CertificateException, NoSuchAlgorithmException {
        ensureGenerated();

        try (BufferedWriter writer = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(certificate);
            pemWriter.flush();
            pemWriter.close();
        }

        return this;
    }

    /**
     * Writes private key in PKCS8 format to a file as PEM.
     *
     * @param Path to write the PEM file to.
     */
    public Credential writePrivateKeyAsPem(Path out) throws IOException, CertificateException, NoSuchAlgorithmException {
        ensureGenerated();

        try (BufferedWriter writer = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(new JcaPKCS8Generator(keyPair.getPrivate(), null));
            pemWriter.flush();
            pemWriter.close();
        }

        return this;
    }

    /**
     * Returns certificate.
     */
    public Certificate getCertificate() throws CertificateException, NoSuchAlgorithmException, CertIOException {
        ensureGenerated();

        return certificate;
    }

    /**
     * Returns certificate as an array.
     * This is convenience method for use cases where array is required.
     *
     * @return Array of certificates. Holds always just single certificate.
     */
    public Certificate[] getCertificates()
            throws CertificateException, NoSuchAlgorithmException, CertIOException {
        ensureGenerated();

        return new Certificate[] { certificate };
    }

    /**
     * Returns certificate.
     * This is convenience for returning certificate as {@code X509Certificate}.
     */
    public X509Certificate getX509Certificate() throws CertificateException, NoSuchAlgorithmException, CertIOException {
        ensureGenerated();

        return (X509Certificate) certificate;
    }

    /**
     * Returns private key.
     */
    public PrivateKey getPrivateKey() throws CertificateException, NoSuchAlgorithmException, CertIOException {
        ensureGenerated();

        return keyPair.getPrivate();
    }


    // Generates certificate and key pair unless they have been already generated.
    private void ensureGenerated()
            throws CertificateException, NoSuchAlgorithmException, CertIOException {
        if (certificate == null || keyPair == null) {
            generate();
        }
    }

    // Fill in defaults for attributes that caller has not set.
    private void setDefaults() {
        if (keyType == null) {
            keyType = KeyType.EC;
        }

        if (keySize == 0) {
            if (keyType == KeyType.EC) {
                keySize = 256;
            } else if (keyType == KeyType.RSA) {
                keySize = 2048;
            }
        }

        if (expires == null && notAfter == null) {
            expires = Duration.of(365, ChronoUnit.DAYS);
        }

        if (isCa == null) {
            boolean noExplicitIssuer = (issuer == null);
            isCa = noExplicitIssuer;
        }

        if (keyUsages.isEmpty()) {
            if (Boolean.TRUE.equals(isCa)) {
                keyUsages = Arrays.asList(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN);
            } else if (keyType == KeyType.EC) {
                // https://github.com/openjdk/jdk/blob/0530f4e517be5d5b3ff10be8a0764e564f068c06/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java#L604-L618
                keyUsages = Arrays.asList(KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_AGREEMENT);
            } else {
                keyUsages = Arrays.asList(KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DIGITAL_SIGNATURE);
            }
        }
    }

    // Returns new key pair.
    private static KeyPair newKeyPair(KeyType keyType, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen;
        keyGen = KeyPairGenerator.getInstance(keyType.name());
        SecureRandom prng = new SecureRandom();
        keyGen.initialize(keySize, prng);
        return keyGen.genKeyPair();
    }

    // Return preferred signature algorithm for given key.
    private static String signatureAlgorithm(PublicKey pub) {
        switch (pub.getAlgorithm()) {
            case "EC":
                EllipticCurve curve = ((ECPublicKey) pub).getParams().getCurve();
                switch (curve.getField().getFieldSize()) {
                    case 224:
                    case 256:
                        return "SHA256withECDSA";
                    case 384:
                        return "SHA384withECDSA";
                    case 521:
                        return "SHA512withECDSA";
                    default:
                        throw new IllegalArgumentException("unknown elliptic curve: " + curve);
                }
            case "RSA":
                return "SHA256WithRSAEncryption";
            default:
                throw new UnsupportedOperationException("unsupported private key algorithm: " + pub.getAlgorithm());
        }
    }

    // Parse string-based subject alt names into GeneralNames.
    private static GeneralNames asGeneralNames(List<String> sans) {
        List<GeneralName> altNames = new ArrayList<>();
        for (String name : sans) {

            // Parse type and value.
            int separatorPos = name.indexOf(":");
            if (separatorPos == -1) {
                throw new IllegalArgumentException("cannot parse " + name
                        + ": all subjectAltNames must be of format: DNS:www.example.com, IP:1.2.3.4, URI:https://www.example.com");
            }
            String type = name.substring(0, separatorPos);
            String value = name.substring(separatorPos + 1);

            // Convert to GeneralName.
            switch (type) {
                case "DNS":
                    altNames.add(new GeneralName(GeneralName.dNSName, value));
                    break;
                case "IP":
                    altNames.add(new GeneralName(GeneralName.iPAddress, value));
                    break;
                case "URI":
                    altNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, value));
                    break;
                default:
                    break;
            }
        }

        if (altNames.isEmpty()) {
            throw new IllegalArgumentException(
                    "subjectAltNames must be of format: DNS:www.example.com, IP:1.2.3.4, URI:https://www.example.com");
        }

        return GeneralNames.getInstance(new DERSequence(altNames.toArray(new GeneralName[] {})));
    }
}
