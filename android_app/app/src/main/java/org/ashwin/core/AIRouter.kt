package org.ashwin.core

class AIRouter(
    private var localAvailable: Boolean = true,
    private var allowCloudDefaultProtected: Boolean = false
) {

    fun processContext(
        context: ScannedClassifiedContext,
        userCloudConsent: Boolean = false
    ): Map<String, Any> {
        if (!context.scanned || context.scanSummary["healthy"] != true) {
            throw RouterGateException("RULE-04 Violation: Missing secret scan state.")
        }
        if (context.dataClass == DataClass.HIGHLY_PROTECTED) {
            throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter model context.")
        }

        val isLocal = when (context.dataClass) {
            DataClass.PUBLIC -> localAvailable
            DataClass.PERSONAL -> localAvailable
            DataClass.PROTECTED -> {
                if (localAvailable) {
                    true
                } else if (userCloudConsent || context.cloudApproved || allowCloudDefaultProtected) {
                    false
                } else {
                    return mapOf(
                        "status" to "DENIED",
                        "reason" to "Missing cloud egress consent while local AI is unavailable.",
                        "message" to "Local AI unavailable. Processing private data with cloud AI requires consent."
                    )
                }
            }
            DataClass.HIGHLY_PROTECTED -> throw SecurityViolationException("RULE-03 Violation.")
        }

        val providerName = if (isLocal) "LocalAI" else "CloudAI"
        val responseText = "[$providerName Response]: Processed context from ${context.source} safely."

        return mapOf(
            "status" to "SUCCESS",
            "provider" to providerName,
            "isLocal" to isLocal,
            "dataClass" to context.dataClass.name,
            "source" to context.source.name,
            "response" to responseText
        )
    }
}
