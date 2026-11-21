/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cookie підписується HMAC-SHA256 серверним ключем замість оборотного
 * кодування reverse+hex+base64 (CWE-327/565). Формат: base64url(value).base64url(HMAC).
 */
public class EncDec {

  private static final byte[] KEY = new byte[32];
  private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DEC = Base64.getUrlDecoder();

  static {
    new SecureRandom().nextBytes(KEY);
  }

  private EncDec() {}

  private static byte[] hmac(byte[] data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
      return mac.doFinal(data);
    } catch (Exception e) {
      throw new IllegalStateException("HMAC error", e);
    }
  }

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }
    byte[] v = value.getBytes(StandardCharsets.UTF_8);
    return ENC.encodeToString(v) + "." + ENC.encodeToString(hmac(v));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }
    int dot = encodedValue.indexOf('.');
    if (dot < 0) {
      throw new IllegalArgumentException("Malformed cookie");
    }
    byte[] v = DEC.decode(encodedValue.substring(0, dot));
    byte[] tag = DEC.decode(encodedValue.substring(dot + 1));
    byte[] expected = hmac(v);
    if (!java.security.MessageDigest.isEqual(expected, tag)) {
      throw new IllegalArgumentException("Invalid cookie signature");
    }
    return new String(v, StandardCharsets.UTF_8);
  }
}
