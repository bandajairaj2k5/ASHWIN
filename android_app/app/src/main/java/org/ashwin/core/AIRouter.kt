package org.ashwin.core

/**
 * ASHWIN AI Provider Interface and AI Router (Phase 3 / Stage C, RULE-01, RULE-03, RULE-04, RULE-05, Section 4).
 * Sole model-delivery boundary. Accepts ONLY typed ScannedClassifiedContext.
 * Cloud routing requires explicit per-request consent for non-public data.
 */
interface AIProvider {
    val name: String
    val isLocal: Boolean
    fun generateResponse(prompt: String): String
}

class LocalAIProvider : AIProvider {
    override val name: String = "LocalAI"
    override val isLocal: Boolean = true
    override fun generateResponse(prompt: String): String {
        return "[LocalAI Response]: Processed prompt safely on device."
    }
}

class CloudAIProvider : AIProvider {
    override val name: String = "CloudAI"
    override val isLocal: Boolean = false
    override fun generateResponse(prompt: String): String {
        return "[CloudAI Response]: Processed prompt via authorized cloud provider."
    }
}

class AIRouter(
    private val localProvider: AIProvider? = LocalAIProvider(),
    private val cloudProvider: AIProvider? = CloudAIProvider(),
    private var localAvailable: Boolean = true
) {

    fun setLocalAvailability(available: Boolean) {
        this.localAvailable = available
    }

    fun processContext(
        context: ScannedClassifiedContext,
        userCloudConsent: Boolean = false
    ): Map<String, Any> {
        if (!context.scanned || context.scanSummary["healthy"] != true) {
            throw RouterGateException("RULE-04 Violation: Context item missing valid scan state.")
        }
        if (context.dataClass == DataClass.HIGHLY_PROTECTED) {
            throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter model context.")
        }

        val targetProvider: AIProvider? = when (context.dataClass) {
            DataClass.PUBLIC -> {
                if (cloudProvider != null) cloudProvider
                else if (localAvailable) localProvider
                else null
            }
            DataClass.PERSONAL -> {
                if (localAvailable && localProvider != null) {
                    localProvider
                } else if (userCloudConsent || context.cloudApproved) {
                    cloudProvider
                } else {
                    null
                }
            }
            DataClass.PROTECTED -> {
                if (localAvailable && localProvider != null) {
                    localProvider
                } else if (userCloudConsent || context.cloudApproved) {
                    cloudProvider
                } else {
                    null
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
                "message" to "The local AI is unavailable. Processing this ${context.dataClass.name} data from ${context.source.name} with cloud AI would send contents outside your device. Allow this for this request?"
            )
        }

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
