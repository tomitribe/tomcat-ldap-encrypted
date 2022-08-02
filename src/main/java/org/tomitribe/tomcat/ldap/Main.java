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

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {
    private Main() {
        // private for checkstyle
    }

    public static void main(String[] args) {
        String input = null;
        String password = null;
        String algorithm = null;

        final List<String> parameters = new ArrayList<>(Arrays.asList(args));

        while (! parameters.isEmpty()) {
            final String head = parameters.remove(0);

            if (head.equals("--input") && (!parameters.isEmpty())) {
                input = parameters.remove(0);
            }
            if (head.equals("--password") && (!parameters.isEmpty())) {
                password = parameters.remove(0);
            }
            if (head.equals("--algorithm") && (!parameters.isEmpty())) {
                algorithm = parameters.remove(0);
            }

            // ignore anything else here
        }

        if (input == null || password == null) {
            System.err.println("Password and input must both be supplied. Example usage: java -jar tomcat-ldap-encrypted-0.0.1-SNAPSHOT.jar  --input [text to encrypt] " +
                    "--password [encryption password]");
            System.exit(1);
        }

        System.out.println("Using input: " + input);
        System.out.println("Using password: " + password);
        System.out.println("Using algorithm: " + (algorithm == null ? "null" : algorithm));

        final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword(password);
        if (algorithm != null) {
            encryptor.setAlgorithm(algorithm);
            // From Jasypt: for PBE-AES-based algorithms, the IV generator is MANDATORY"
            if (algorithm.startsWith("PBE") && algorithm.contains("AES")) {
                encryptor.setIvGenerator(new RandomIvGenerator());
            }
        }

        System.out.println("Encrypted text: " + encryptor.encrypt(input));
    }
}
