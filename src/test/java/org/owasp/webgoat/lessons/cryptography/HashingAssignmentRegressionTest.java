/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Регресійний тест вразливості 3 (несолені швидкі хеші, CWE-328/916/759). */
class HashingAssignmentRegressionTest {

  private final HashingAssignment endpoint = new HashingAssignment();

  @Test
  @DisplayName("Ендпойнти повертають солений bcrypt, а не 32/64-символьний hex MD5/SHA-256")
  void hashesAreSaltedBcrypt() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    for (String hash : new String[] {endpoint.getMd5(request), endpoint.getSha256(request)}) {
      assertThat(hash).startsWith("$2").hasSize(60);
      assertThat(hash).doesNotMatch("^[0-9A-Fa-f]{32}$|^[0-9A-Fa-f]{64}$");
    }
  }

  @Test
  @DisplayName("Хеш пароля із сесії перевіряється bcrypt-ом і не збігається зі словниковим MD5")
  void hashMatchesStoredSecretOnlyViaBcrypt() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    String hash = endpoint.getMd5(request);
    String secret = (String) request.getSession().getAttribute("md5Secret");
    assertThat(new BCryptPasswordEncoder().matches(secret, hash)).isTrue();
    assertThat(hash).isNotEqualToIgnoringCase(md5Hex(secret));
  }

  @Test
  @DisplayName("Сіль випадкова: два хеші одного пароля різняться")
  void saltIsRandom() {
    BCryptPasswordEncoder enc = new BCryptPasswordEncoder(4);
    assertThat(enc.encode("secret")).isNotEqualTo(enc.encode("secret"));
  }

  private static String md5Hex(String s) throws Exception {
    byte[] d = java.security.MessageDigest.getInstance("MD5").digest(s.getBytes());
    return jakarta.xml.bind.DatatypeConverter.printHexBinary(d);
  }
}
