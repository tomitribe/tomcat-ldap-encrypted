/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.tomitribe.tomcat.ldap;

import org.apache.catalina.realm.JNDIRealm;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.iv.RandomIvGenerator;

public class EncryptedJNDIRealm extends JNDIRealm {

    protected String encryptedConnectionPassword;
    protected String algorithm;

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getEncryptedConnectionPassword() {
        return encryptedConnectionPassword;
    }

    public void setEncryptedConnectionPassword(final String encryptedPassword) {
        this.encryptedConnectionPassword = encryptedPassword;

        final String password = System.getenv("TOMCAT_ENCRYPTION_PASSWORD");
        if (password == null) {
            return;
        }

        final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword(password);
        if (algorithm != null) {
            encryptor.setAlgorithm(algorithm);
            // From Jasypt: for PBE-AES-based algorithms, the IV generator is MANDATORY"
            if (algorithm.startsWith("PBE") && algorithm.contains("AES")) {
                encryptor.setIvGenerator(new RandomIvGenerator());
            }
        }
        try {
            final String decrypted = encryptor.decrypt(encryptedPassword);
            this.setConnectionPassword(decrypted);
        } catch (EncryptionOperationNotPossibleException e) {
            throw new RuntimeException("ERROR: Text cannot be decrypted, check your input and password and try again!", e);
        }
    }
}
