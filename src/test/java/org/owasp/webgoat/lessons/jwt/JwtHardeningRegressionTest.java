/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.TextCodec;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Регресійні тести для вразливостей 1 (слабкий ключ JWT) і 4 (JWT alg:none). */
class JwtHardeningRegressionTest {

  private static final List<String> OLD_DICTIONARY =
      List.of("victory", "business", "available", "shipping", "washington");

  @Test
  @DisplayName("CWE-326/330: ключ підпису не збігається зі словниковим і має >= 256 біт")
  void secretIsNotDictionaryWord() {
    byte[] key = TextCodec.BASE64.decode(JWTSecretKeyEndpoint.JWT_SECRET);
    assertThat(key.length).isGreaterThanOrEqualTo(32);
    for (String word : OLD_DICTIONARY) {
      assertThat(new String(key)).isNotEqualTo(word);
    }
  }

  @Test
  @DisplayName("CWE-326: токен, підписаний словниковим секретом, не проходить перевірку")
  void dictionarySignedTokenRejected() {
    for (String word : OLD_DICTIONARY) {
      String forged =
          Jwts.builder()
              .claim("user", "Tom")
              .signWith(SignatureAlgorithm.HS256, TextCodec.BASE64.encode(word))
              .compact();
      assertThatThrownBy(
              () ->
                  Jwts.parser()
                      .setSigningKey(JWTSecretKeyEndpoint.JWT_SECRET)
                      .parseClaimsJws(forged))
          .isInstanceOf(SignatureException.class);
    }
  }

  @Test
  @DisplayName("CWE-347: непідписаний токен (alg:none) відхиляється parseClaimsJws")
  void algNoneRejected() {
    String unsigned = Jwts.builder().claim("user", "Tom").claim("admin", "true").compact();
    assertThatThrownBy(
            () -> Jwts.parser().setSigningKey(JWTVotesEndpoint.JWT_PASSWORD).parseClaimsJws(unsigned))
        .isInstanceOf(UnsupportedJwtException.class);
  }

  @Test
  @DisplayName("Контроль: коректно підписаний токен приймається")
  void validSignedTokenAccepted() {
    String token =
        Jwts.builder()
            .claim("user", "Tom")
            .signWith(SignatureAlgorithm.HS512, JWTVotesEndpoint.JWT_PASSWORD)
            .compact();
    assertThat(
            Jwts.parser()
                .setSigningKey(JWTVotesEndpoint.JWT_PASSWORD)
                .parseClaimsJws(token)
                .getBody()
                .get("user"))
        .isEqualTo("Tom");
  }
}
