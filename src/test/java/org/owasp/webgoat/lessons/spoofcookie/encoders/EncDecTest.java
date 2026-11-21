/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Тести cookie з підписом HMAC: розкодування, відхилення підробки й зміни. */
class EncDecTest {

  @Test
  @DisplayName("Пара encode/decode повертає вихідне значення")
  void roundTrip() {
    for (String v : new String[] {"webgoat", "admin", "tom"}) {
      assertThat(EncDec.decode(EncDec.encode(v))).isEqualTo(v);
    }
  }

  @Test
  @DisplayName("Регресія CWE-565: підроблений cookie з валідним payload відхиляється")
  void forgedCookieRejected() {
    java.util.Base64.Encoder enc = java.util.Base64.getUrlEncoder().withoutPadding();
    String forged =
        enc.encodeToString("tom".getBytes(java.nio.charset.StandardCharsets.UTF_8))
            + "."
            + enc.encodeToString("not-a-valid-hmac".getBytes());
    assertThatThrownBy(() -> EncDec.decode(forged))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("Модифікація payload недійсна (цілісність під HMAC)")
  void tamperedPayloadRejected() {
    String valid = EncDec.encode("webgoat");
    String tag = valid.substring(valid.indexOf('.'));
    java.util.Base64.Encoder enc = java.util.Base64.getUrlEncoder().withoutPadding();
    String tampered = enc.encodeToString("admin".getBytes()) + tag;
    assertThatThrownBy(() -> EncDec.decode(tampered))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("null encode/decode")
  void nulls() {
    assertThat(EncDec.encode(null)).isNull();
    assertThat(EncDec.decode(null)).isNull();
  }
}
