package org.ashwin.core

import java.util.UUID

enum class ConsentDecisionType {
    GRANTED_ONCE,
    DENIED
}

/**
 * Minimal metadata presented for user consent resolution.
 * Strictly contains NO raw context text or private data strings (Section 4.7).
 */
data class ConsentMetadata(
    val sourceDomain: SourceDomain,
    val dataClass: DataClass,
    val targetProvider: String,
    val rationale: String,
    val requestId: String = UUID.randomUUID().toString()
)

/**
 * Structured, ephemeral authorization bound to the exact request/turn,
 * target provider, source domain, data classification, and context identity.
 * Consumed immediately upon use (Section 4.5).
 */
data class CloudConsentToken(
    val requestId: String,
    val sourceDomain: SourceDomain,
    val dataClass: DataClass,
    val targetProvider: String,
    val tokenId: String = UUID.randomUUID().toString(),
    val createdAt: Long = System.currentTimeMillis()
) {
    private var consumed: Boolean = false

    fun isValidFor(context: ScannedClassifiedContext, targetProviderName: String, expectedRequestId: String? = null): Boolean {
        if (consumed) return false
        if (expectedRequestId != null && requestId != expectedRequestId) return false
        if (sourceDomain != context.source) return false
        if (dataClass != context.dataClass) return false
        if (targetProvider != targetProviderName) return false
        return true
    }

    fun isConsumed(): Boolean = consumed

    fun consume() {
        if (consumed) {
            throw SecurityViolationException("ConsentToken has already been consumed.")
        }
        consumed = true
    }
}

/**
 * Interface for interactive consent resolution.
 */
interface ConsentCoordinator {
    fun requestConsent(metadata: ConsentMetadata, onDecision: (CloudConsentToken?) -> Unit)
}

class CallbackConsentCoordinator(
    private val handler: (ConsentMetadata, (CloudConsentToken?) -> Unit) -> Unit
) : ConsentCoordinator {
    override fun requestConsent(metadata: ConsentMetadata, onDecision: (CloudConsentToken?) -> Unit) {
        handler(metadata, onDecision)
    }
}

