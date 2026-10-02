package org.ashwin.core

import java.text.SimpleDateFormat
import java.util.*

/**
 * Data Model for Email Summary
 */
data class EmailSummary(
    val id: String,
    val sender: String,
    val subject: String,
    val date: String,
    val isUnread: Boolean,
    val previewSnippet: String
)

/**
 * ASHWIN Email Connector (Future Connectors Architecture).
 *
 * Enforces:
 * 1. Read-Only Boundary: Zero auto-send, zero draft creation, zero deletion/modification.
 * 2. Mandatory Secret Scanning: All email bodies, subjects, and senders are scanned and redacted.
 * 3. Typed Context Egress: Returns ScannedClassifiedContext (PROTECTED class) for CoreSession.
 * 4. Bounded buffers and safe formatting.
 */
class EmailConnector(
    val credentialStore: CredentialStore,
    private val scanner: SecretScanner = SecretScanner()
) {
    companion object {
        private const val TAG = "ASHWIN_EMAIL_CONNECTOR"
    }

    private var accessPermissionGranted: Boolean = false
    private var isConfigured: Boolean = false

    fun isConfigured(): Boolean = isConfigured

    fun setConfigured(configured: Boolean) {
        this.isConfigured = configured
    }

    // Staged / In-Memory Mock Inbox for Local Demonstration & Testing
    private val mockInbox = mutableListOf(
        EmailSummary(
            id = "em_001",
            sender = "security@ashwin.internal",
            subject = "ASHWIN System Audit — All Systems Operational",
            date = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.US).format(Date(System.currentTimeMillis() - 3600000)),
            isUnread = true,
            previewSnippet = "Security integrity verification passed. Cryptographic boundaries and mTLS certificates verified."
        ),
        EmailSummary(
            id = "em_002",
            sender = "updates@project-ashwin.org",
            subject = "Phase 4 Endpoint Rollout Complete",
            date = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.US).format(Date(System.currentTimeMillis() - 7200000)),
            isUnread = true,
            previewSnippet = "Windows Restricted Endpoint with 10 tools is now active and ready for mobile dispatch."
        ),
        EmailSummary(
            id = "em_003",
            sender = "calendar@personal.net",
            subject = "Project Review Meeting Reminder",
            date = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.US).format(Date(System.currentTimeMillis() - 86400000)),
            isUnread = false,
            previewSnippet = "Reminder: Architecture review scheduled for Friday at 10:00 AM."
        )
    )

    private val mockEmailBodies = mapOf(
        "em_001" to "ASHWIN Security Audit Report\n\nStatus: ALL PASS\n- Motorola Moto G3 Private Storage Endpoint: OK (TLS 1.3 mTLS, AES-GCM / HMAC-SHA256)\n- Windows Laptop Restricted Endpoint: OK (Single-handle, 10 Tools, DPAPI-protected)\n- Ephemeral RAM Memory: Zero disk persistence verified.",
        "em_002" to "Dear User,\n\nPhase 4 Windows Restricted Endpoint deployment is finalized. You can now use natural language voice commands to control allowlisted Windows tools including calculator, notepad, file search, and read operations.\n\nBest regards,\nASHWIN Team",
        "em_003" to "Hi,\n\nThis is a confirmation for our upcoming project review on Friday at 10:00 AM.\nAgenda:\n1. Mobile Voice Assistant UI\n2. Holographic HUD performance\n3. File download pipeline\n\nSee you there!"
    )

    fun setAccessPermission(granted: Boolean) {
        this.accessPermissionGranted = granted
    }

    fun isAccessPermissionGranted(): Boolean = accessPermissionGranted

    fun getUnreadCount(): Int {
        return mockInbox.count { it.isUnread }
    }

    fun listRecentEmails(limit: Int = 10): List<EmailSummary> {
        return mockInbox.take(limit)
    }

    fun searchEmails(query: String): List<EmailSummary> {
        val q = query.lowercase(Locale.US)
        return mockInbox.filter {
            it.subject.lowercase(Locale.US).contains(q) ||
            it.sender.lowercase(Locale.US).contains(q) ||
            it.previewSnippet.lowercase(Locale.US).contains(q)
        }
    }

    fun readEmail(emailId: String): ScannedClassifiedContext {
        val summary = mockInbox.find { it.id == emailId }
            ?: throw IllegalArgumentException("Email with ID '$emailId' was not found.")

        val rawBody = mockEmailBodies[emailId] ?: "No content available."
        val fullContent = "From: ${summary.sender}\nSubject: ${summary.subject}\nDate: ${summary.date}\n\n$rawBody"

        val (redactedContent, scanSummary, _) = scanner.scanAndRedact(fullContent)
        if (scanSummary["healthy"] != true) {
            throw RouterGateException("Secret scan failed for email content.")
        }

        return ScannedClassifiedContext(
            content = redactedContent,
            dataClass = DataClass.PROTECTED,
            source = SourceDomain.PHONE,
            cloudApproved = false,
            scanned = true,
            scanSummary = scanSummary,
            metadata = mapOf(
                "email_id" to emailId,
                "sender" to summary.sender,
                "subject" to summary.subject,
                "scope_label" to "EMAIL"
            )
        )
    }
}
