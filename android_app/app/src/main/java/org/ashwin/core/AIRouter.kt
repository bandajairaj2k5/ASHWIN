package org.ashwin.core

/**
 * ASHWIN AI Router (Phase 3 / Stage C & D, RULE-01, RULE-03, RULE-04, RULE-05, Section 4).
 * Sole model-delivery boundary. Accepts ONLY typed ScannedClassifiedContext.
 * Cloud routing requires explicit per-request consent for non-public data.
 */
class AIRouter(
    val localProvider: AIProvider? = LocalAIProvider(),
    val cloudProvider: AIProvider? = CloudAIProvider(),
    private var localAvailable: Boolean = true
) {

    fun setLocalAvailability(available: Boolean) {
        this.localAvailable = available
    }

    fun isLocalAvailable(): Boolean = localAvailable

    fun processContext(
        context: ScannedClassifiedContext,
        userCloudConsent: Boolean = false,
        consentToken: CloudConsentToken? = null
    ): Map<String, Any> {
        if (!context.scanned || context.scanSummary["healthy"] != true) {
            throw RouterGateException("RULE-04 Violation: Context item missing valid scan state.")
        }
        if (context.dataClass == DataClass.HIGHLY_PROTECTED) {
            throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter model context.")
        }

        fun checkCloudConsent(): Pair<Boolean, CloudConsentToken?> {
            if (cloudProvider == null) return Pair(false, null)
            if (consentToken != null) {
                if (!consentToken.isValidFor(context, cloudProvider.name)) {
                    throw SecurityViolationException("RULE-01 Violation: Consent token is invalid, mismatched, or already consumed.")
                }
                return Pair(true, consentToken)
            }
            if (userCloudConsent || context.cloudApproved) {
                val ephemeralToken = CloudConsentToken(
                    requestId = "DIRECT_CALL",
                    sourceDomain = context.source,
                    dataClass = context.dataClass,
                    targetProvider = cloudProvider.name
                )
                return Pair(true, ephemeralToken)
            }
            return Pair(false, null)
        }

        var tokenToConsume: CloudConsentToken? = null

        val targetProvider: AIProvider? = when (context.dataClass) {
            DataClass.PUBLIC -> {
                if (cloudProvider != null) cloudProvider
                else if (localAvailable) localProvider
                else null
            }
            DataClass.PERSONAL -> {
                if (localAvailable && localProvider != null) {
                    localProvider
                } else {
                    val (hasConsent, token) = checkCloudConsent()
                    if (hasConsent) {
                        tokenToConsume = token
                        cloudProvider
                    } else null
                }
            }
            DataClass.PROTECTED -> {
                if (localAvailable && localProvider != null) {
                    localProvider
                } else {
                    val (hasConsent, token) = checkCloudConsent()
                    if (hasConsent) {
                        tokenToConsume = token
                        cloudProvider
                    } else null
                }
            }
            DataClass.HIGHLY_PROTECTED -> {
                throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter model context.")
            }
        }

        if (targetProvider == null) {
            return mapOf(
                "status" to "DENIED",
                "reason" to "Missing cloud egress consent while local AI is unavailable or prohibited.",
                "user_prompt_required" to true,
                "data_class" to context.dataClass.name,
                "source" to context.source.name,
                "target_provider" to (cloudProvider?.name ?: "CloudAI"),
                "message" to "The local AI is unavailable. Processing this ${context.dataClass.name} data from ${context.source.name} with cloud AI would send contents outside your device. Allow this for this request?"
            )
        }

        // Consume ephemeral token
        tokenToConsume?.consume()

        val responseText = targetProvider.generateResponse(context.content)

        return mapOf(
            "status" to "SUCCESS",
            "provider_used" to targetProvider.name,
            "is_local" to targetProvider.isLocal,
            "data_class" to context.dataClass.name,
            "source" to context.source.name,
            "response" to responseText
        )
    }
}
