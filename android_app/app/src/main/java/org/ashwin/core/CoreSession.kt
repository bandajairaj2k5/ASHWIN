package org.ashwin.core

import android.util.Log
import java.util.UUID

class CoreSessionException(message: String) : Exception(message)

/**
 * ASHWIN Core Session Coordinator (Phase 3 / Stage A & E, Section 2, Section 5, Section 12).
 *
 * Coordinates execution lifecycle, component binding, and fail-closed state.
 */
class CoreSession(
    val credentialStore: CredentialStore,
    val scanner: SecretScanner = SecretScanner(),
    val memoryStore: EphemeralMemoryStore = EphemeralMemoryStore(scanner),
    val classifier: InputClassifier = InputClassifier(scanner),
    val router: AIRouter = AIRouter()
) {
    companion object {
        private const val TAG = "ASHWIN_CORE_SESSION"
    }

    var sessionId: String = UUID.randomUUID().toString()
        private set
    var createdAt: Long = System.currentTimeMillis()
        private set
    var isActive: Boolean = true
        private set

    init {
        verifyHealth()
        Log.i(TAG, "CoreSession initialized: sessionId=$sessionId")
    }

    private fun verifyHealth() {
        val testScan = scanner.scanAndRedact("HEALTH_CHECK")
        if (testScan.second["healthy"] != true) {
            isActive = false
            throw CoreSessionException("CoreSession initialization failed: SecretScanner is unhealthy.")
        }
    }

    fun isHealthy(): Boolean {
        return isActive && (scanner.scanAndRedact("PING").second["healthy"] == true)
    }

    fun executeTurn(
        rawText: String,
        source: SourceDomain = SourceDomain.PHONE,
        isStt: Boolean = false,
        consentCoordinator: ConsentCoordinator? = null,
        callback: (Map<String, Any>) -> Unit
    ) {
        if (!isActive) {
            callback(mapOf("status" to "ERROR", "message" to "CoreSession is inactive. Ingress rejected."))
            return
        }

        // Step 1: Input Classification & Secret Scanning
        val classifiedContext: ScannedClassifiedContext
        try {
            classifiedContext = classifier.processUserInput(
                rawText = rawText,
                source = source,
                isStt = isStt
            )
        } catch (e: Exception) {
            Log.e(TAG, "Input classification rejected: ${e.message}")
            callback(mapOf(
                "status" to "BLOCKED",
                "message" to "RULE-03 / RULE-04 Violation: Classification failed closed: ${e.message}"
            ))
            return
        }

        // Step 2: Early Hard Fail-Closed for HIGHLY_PROTECTED (RULE-03)
        if (classifiedContext.dataClass == DataClass.HIGHLY_PROTECTED) {
            Log.e(TAG, "HIGHLY_PROTECTED data blocked before memory or model ingress.")
            callback(mapOf(
                "status" to "BLOCKED",
                "message" to "RULE-03 Violation: HIGHLY_PROTECTED data cannot enter memory or model context."
            ))
            return
        }

        // Step 3: Ephemeral RAM memory store insertion
        memoryStore.addContext(classifiedContext)

        // Step 4: First AIRouter execution attempt
        val routerResult = router.processContext(classifiedContext)

        if (routerResult["status"] == "SUCCESS") {
            callback(routerResult)
            return
        }

        // Step 5: Interactive Cloud Consent resolution
        val promptRequired = routerResult["user_prompt_required"] as? Boolean ?: false
        if (promptRequired && consentCoordinator != null) {
            val metadata = ConsentMetadata(
                sourceDomain = classifiedContext.source,
                dataClass = classifiedContext.dataClass,
                targetProvider = routerResult["target_provider"] as? String ?: "CloudAI",
                rationale = "Local AI is unavailable. Sending ${classifiedContext.dataClass.name} data from ${classifiedContext.source.name} to Cloud AI requires your explicit consent."
            )

            consentCoordinator.requestConsent(metadata) { consentToken ->
                if (consentToken != null) {
                    val secondResult = router.processContext(
                        context = classifiedContext,
                        consentToken = consentToken
                    )
                    callback(secondResult)
                } else {
                    callback(mapOf(
                        "status" to "DENIED",
                        "reason" to "Cloud AI consent was denied by user. Private data was not transmitted.",
                        "user_prompt_required" to false,
                        "data_class" to classifiedContext.dataClass.name,
                        "source" to classifiedContext.source.name,
                        "message" to "Cloud AI consent was denied by user. Private data was not transmitted."
                    ))
                }
            }
            return
        }

        callback(routerResult)
    }

    fun resetSession() {
        val oldSessionId = sessionId
        sessionId = UUID.randomUUID().toString()
        createdAt = System.currentTimeMillis()
        isActive = true
        memoryStore.clear()
        verifyHealth()
        Log.i(TAG, "CoreSession reset: oldSessionId=$oldSessionId, newSessionId=$sessionId")
    }

    fun terminateSession() {
        isActive = false
        memoryStore.clear()
        Log.i(TAG, "CoreSession terminated: sessionId=$sessionId")
    }
}
