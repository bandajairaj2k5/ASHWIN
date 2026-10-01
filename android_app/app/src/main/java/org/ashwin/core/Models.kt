package org.ashwin.core

enum class DataClass {
    PUBLIC,
    PERSONAL,
    PROTECTED,
    HIGHLY_PROTECTED
}

enum class SourceDomain {
    PHONE,
    MOTO_STORAGE,
    LAPTOP,
    GMAIL,
    CALENDAR,
    GITHUB,
    LINKEDIN,
    WEB
}

class RouterGateException(message: String) : Exception(message)
class SecurityViolationException(message: String) : Exception(message)

data class ScannedClassifiedContext(
    val content: String,
    val dataClass: DataClass,
    val source: SourceDomain,
    val cloudApproved: Boolean = false,
    val scanned: Boolean = false,
    val scanSummary: Map<String, Any> = emptyMap(),
    val metadata: Map<String, Any> = emptyMap(),
    val timestamp: Long = System.currentTimeMillis()
) {
    init {
        // RULE-04 Gate check
        if (!scanned) {
            throw RouterGateException("Context rejected: Missing valid secret scan state.")
        }
        if (scanSummary["healthy"] != true) {
            throw RouterGateException("Context rejected: Secret scanner health check failed.")
        }
        // RULE-03 Check
        if (dataClass == DataClass.HIGHLY_PROTECTED) {
            throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter model context.")
        }
    }
}
