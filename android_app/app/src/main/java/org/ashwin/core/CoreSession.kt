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
