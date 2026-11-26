/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.theme

import java.io.File
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/**
 * Guards the cache-busting contract of the plugin-provided JavaScript resources
 * (SERVKO-4490).
 *
 * The scripts referenced in `themes/gematik-idp/login/theme.properties` carry a
 * `?v=${env.GEMATIK_IDP_VERSION}` query parameter so that browsers fetch the
 * updated JavaScript after a plugin deployment. The value is substituted by
 * Keycloak from the `GEMATIK_IDP_VERSION` environment variable, which the
 * deployment must provision with the deployed plugin's Maven version.
 */
internal class ThemeCacheBustingTest {

    private companion object {
        const val THEME_PROPERTIES_FILE = "themes/gematik-idp/login/theme.properties"
        const val VERSION_PLACEHOLDER = "\${env.GEMATIK_IDP_VERSION}"
        val PLUGIN_SCRIPTS = listOf(
            "js/gematik-idp.js",
            "js/utils/freePortHelper.js",
            "js/polling/localHTTPServerPoller.js",
        )
    }

    private val scripts: List<String> by lazy {
        val file = File(THEME_PROPERTIES_FILE)
        check(file.isFile) {
            "Cannot locate $THEME_PROPERTIES_FILE — the test must be run from the module basedir (e.g. mvn test)."
        }
        val properties = java.util.Properties()
        file.inputStream().use { properties.load(it) }
        checkNotNull(properties.getProperty("scripts")) { "theme.properties must define a scripts entry" }
            .trim()
            .split(Regex("\\s+"))
    }

    @ParameterizedTest
    @ValueSource(strings = ["js/gematik-idp.js", "js/utils/freePortHelper.js", "js/polling/localHTTPServerPoller.js"])
    fun `plugin scripts are versioned with the GEMATIK_IDP_VERSION placeholder`(script: String) {
        assertThat(scripts)
            .contains("${script}?v=${VERSION_PLACEHOLDER}")
    }

    @Test
    fun `all plugin scripts share a single cache-busting identifier`() {
        val identifiers = PLUGIN_SCRIPTS.map { script ->
            val entry = scripts.singleOrNull { it.substringBefore('?') == script }
                ?: throw AssertionError("theme.properties contains no versioned entry for $script")
            entry.substringAfter('?')
        }

        assertThat(identifiers)
            .containsExactlyElementsOf(List(PLUGIN_SCRIPTS.size) { "v=${VERSION_PLACEHOLDER}" })
    }

    @Test
    fun `substituting the version produces distinct and stable urls`() {
        fun rendered(version: String): List<String> =
            scripts.map { entry -> entry.replace(VERSION_PLACEHOLDER, version) }

        val firstRender = rendered("3.47.0")
        val secondRender = rendered("3.47.0")
        val nextVersionRender = rendered("3.47.1")

        assertThat(firstRender).containsExactly(
            "js/gematik-idp.js?v=3.47.0",
            "js/utils/freePortHelper.js?v=3.47.0",
            "js/polling/localHTTPServerPoller.js?v=3.47.0",
        )
        assertThat(firstRender).isEqualTo(secondRender)
        assertThat(nextVersionRender).isNotEqualTo(firstRender)
    }
}
