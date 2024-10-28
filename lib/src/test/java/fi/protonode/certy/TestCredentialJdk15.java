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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.X509Certificate;
import java.security.interfaces.EdECPublicKey;

import org.junit.jupiter.api.Test;

import fi.protonode.certy.Credential.KeyType;

/**
 * Test cases for Credential class using JDK 15 and later.
 */
class TestCredentialJdk15 {

    @Test
    void testEd25519Certificate() throws Exception {
        Credential cred = new Credential().subject("CN=joe")
                .keyType(KeyType.ED25519);
        X509Certificate cert = cred.getX509Certificate();
        assertNotNull(cert);
        EdECPublicKey key = (EdECPublicKey) cert.getPublicKey();
        assertEquals("Ed25519", key.getAlgorithm());
    }

    @Test
    void testInvalidKeySize() {
        Credential cred3 = new Credential().subject("CN=joe").keyType(KeyType.ED25519).keySize(1);
        assertThrows(IllegalArgumentException.class, () -> cred3.getX509Certificate());
    }

}
