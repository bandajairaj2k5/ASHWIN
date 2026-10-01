package org.ashwin.core

/**
 * ASHWIN Input Classifier & Ingestion Pipeline (Phase 3 / Stage B, Section 4.3, Section 5, RULE-03, RULE-04).
 *
 * Enforces:
 * 1. Typed user input and STT transcriptions are PROTECTED by default (Section 4.3).
 * 2. Mandatory secret scanning before wrapping into ScannedClassifiedContext.
 * 3. Any material successfully identified as HIGHLY_PROTECTED is blocked from all model contexts.
 *    (Natural-language secret-detection limitations remain those defined by the frozen v1.0.1 specification).
 */
class InputClassifier(
    private val scanner: SecretScanner = SecretScanner()
) {

    fun processUserInput(
        rawText: String,
        source: SourceDomain = SourceDomain.PHONE,
        isStt: Boolean = false,
        cloudApproved: Boolean = false,
        metadata: Map<String, Any> = emptyMap()
    ): ScannedClassifiedContext {
        val (redactedContent, scanSummary, assessedClass) = scanner.scanAndRedact(rawText)

        if (scanSummary["healthy"] != true) {
            throw RouterGateException("Classification rejected: SecretScanner is unhealthy.")
        }

        // Section 4.3: Default classification for user input (typed or STT) is PROTECTED
        val finalClass = if (assessedClass == DataClass.HIGHLY_PROTECTED) {
            DataClass.HIGHLY_PROTECTED
        } else {
            DataClass.PROTECTED
        }

        val enrichedMeta = metadata.toMutableMap().apply {
            put("input_type", if (isStt) "STT" else "TYPED_TEXT")
            put("source_domain", source.name)
            put("redaction_count", scanSummary["redaction_count"] ?: 0)
        }

        return ScannedClassifiedContext(
            content = redactedContent,
            dataClass = finalClass,
            source = source,
            cloudApproved = cloudApproved,
            scanned = true,
            scanSummary = scanSummary,
            metadata = enrichedMeta
        )
    }

    fun processExternalContent(
        content: String,
        source: SourceDomain,
        defaultClass: DataClass = DataClass.PROTECTED,
        cloudApproved: Boolean = false,
        metadata: Map<String, Any> = emptyMap()
    ): ScannedClassifiedContext {
        val (redactedContent, scanSummary, assessedClass) = scanner.scanAndRedact(content)

        if (scanSummary["healthy"] != true) {
            throw RouterGateException("Classification rejected: SecretScanner is unhealthy.")
        }

        val finalClass = if (assessedClass == DataClass.HIGHLY_PROTECTED) {
            DataClass.HIGHLY_PROTECTED
        } else {
            defaultClass
        }

        return ScannedClassifiedContext(
            content = redactedContent,
            dataClass = finalClass,
            source = source,
            cloudApproved = cloudApproved,
            scanned = true,
            scanSummary = scanSummary,
            metadata = metadata
        )
    }
}
