package org.ashwin.core

import java.io.File

/**
 * ASHWIN Location Formatter (RULE-15).
 * Ensures the AI model receives ONLY minimum safe location representations (Scope label + allowlisted name).
 * Prevents drive letters, raw Android storage paths, or full filesystem paths from entering model context.
 */
object LocationFormatter {

    fun formatForModel(scopeLabel: String, filename: String): String {
        val safeName = File(filename).name
        val safeLabel = scopeLabel.trim('/', '\\')
        return "$safeLabel/$safeName"
    }

    fun stripRawPathsFromText(text: String, scopeMappings: Map<String, String>): String {
        var sanitized = text
        for ((scopeLabel, rawPath) in scopeMappings) {
            if (rawPath.isNotBlank() && sanitized.contains(rawPath)) {
                sanitized = sanitized.replace(rawPath, "[$scopeLabel]")
            }
        }
        return sanitized
    }
}
