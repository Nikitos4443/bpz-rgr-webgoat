/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Регресійний тест вразливості 5 (облікові дані у клієнтському JS, CWE-319/798). */
class HardcodedCredentialsRegressionTest {

  @ParameterizedTest(name = "{0} не містить вшитих облікових даних")
  @ValueSource(
      strings = {
        "src/main/resources/lessons/insecurelogin/js/credentials.js",
        "src/main/resources/lessons/ssrf/js/credentials.js"
      })
  void noHardcodedCredentials(String path) throws Exception {
    String js = Files.readString(Path.of(path), StandardCharsets.UTF_8);
    // старі значення були у вигляді \x-екранованих рядків CaptainJack / BlackPearl
    assertThat(js).doesNotContain("\\x43\\x61\\x70\\x74").doesNotContain("_0xb7f9");
    assertThat(js).doesNotContain("CaptainJack").doesNotContain("BlackPearl");
  }
}
