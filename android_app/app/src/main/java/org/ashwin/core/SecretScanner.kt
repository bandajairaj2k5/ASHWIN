package org.ashwin.core

import java.util.regex.Pattern

class SecretScanner(private var healthy: Boolean = true) {

    private val patterns = listOf(
        Pair(Pattern.compile("-----BEGIN\\s+[A-Z\\s]+PRIVATE\\s+KEY-----[\\s\\S]*?-----END\\s+[A-Z\\s]+PRIVATE\\s+KEY-----", Pattern.CASE_INSENSITIVE), "PRIVATE_KEY"),
        Pair(Pattern.compile("sk-[a-zA-Z0-9]{16,}", Pattern.CASE_INSENSITIVE), "API_KEY"),
        Pair(Pattern.compile("AKIA[0-9A-Z]{16}", Pattern.CASE_INSENSITIVE), "API_KEY"),
        Pair(Pattern.compile("ghp_[a-zA-Z0-9]{36}", Pattern.CASE_INSENSITIVE), "API_KEY"),
        Pair(Pattern.compile("(api[_-]?key|secret[_-]?key|access[_-]?token)\\s*[:=]\\s*[\"']?([a-zA-Z0-9_-]{16,})[\"']?", Pattern.CASE_INSENSITIVE), "API_KEY"),
        Pair(Pattern.compile("(password|passwd|pwd)\\s*[:=]\\s*[\"']?([^\\s\"']{4,})[\"']?", Pattern.CASE_INSENSITIVE), "PASSWORD"),
        Pair(Pattern.compile("eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+", Pattern.CASE_INSENSITIVE), "OAUTH_TOKEN"),
        Pair(Pattern.compile("[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}", Pattern.CASE_INSENSITIVE), "RECOVERY_CODE")
    )

    fun scanAndRedact(input: String): Triple<String, Map<String, Any>, DataClass> {
        if (!healthy) {
            return Triple(input, mapOf("healthy" to false, "error" to "Scanner unhealthy"), DataClass.HIGHLY_PROTECTED)
        }
        var redacted = input
        var totalRedactions = 0
        val redactionCounts = mutableMapOf<String, Int>()

        for ((pattern, secretType) in patterns) {
            val matcher = pattern.matcher(redacted)
            if (matcher.find()) {
                val replacement = "[REDACTED:$secretType]"
                redacted = matcher.replaceAll(replacement)
                totalRedactions++
                redactionCounts[secretType] = (redactionCounts[secretType] ?: 0) + 1
            }
        }

        val summary = mapOf(
            "healthy" to true,
            "redaction_count" to totalRedactions,
            "redactions" to redactionCounts
        )

        return Triple(redacted, summary, DataClass.PROTECTED)
    }
}
