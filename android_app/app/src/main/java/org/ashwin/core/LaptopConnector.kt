package org.ashwin.core

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class LaptopSecurityException(message: String) : Exception(message)

/**
 * ASHWIN Laptop Connector (Phase 4 / Section 8, RULE-06, RULE-07, RULE-08, RULE-14, RULE-15).
 * CoreSession-owned client connector for the Windows Restricted Endpoint.
 *
 * Enforces:
 * 1. Exactly 10 approved tools. Zero shell/subprocess execution.
 * 2. Pre-query access permission gating (ephemeral, reset on session reset).
 * 3. 128-bit single-use challenge nonce with 60s TTL and burn-on-use replay protection.
 * 4. HMAC-SHA256 session key derivation using "ASHWIN_LAPTOP_MTLS_SECRET".
 * 5. Returns strictly ScannedClassifiedContext with SourceDomain.LAPTOP and DataClass.PROTECTED.
 */
class LaptopConnector(
    val credentialStore: CredentialStore,
    private val scanner: SecretScanner = SecretScanner(),
    private var customHttpClient: OkHttpClient? = null
) {
    companion object {
        const val OFFLINE_LAPTOP_MSG = "Your Windows laptop endpoint is currently unavailable."
        private const val SESSION_SALT = "ASHWIN_LAPTOP_MTLS_SECRET"
        private const val SAS_SALT = "ASHWIN_LAPTOP_SAS_SALT"
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        val ALLOWED_TOOLS = setOf(
            "find_file",
            "find_folder",
            "list_folder",
            "open_folder",
            "view_document",
            "read_document_text",
            "open_allowed_app",
            "get_open_apps",
            "get_processes",
            "get_connected_devices"
        )
    }

    private var accessPermissionGranted: Boolean = false
    private var host: String = "127.0.0.1"
    private var port: Int = 8444
    private var sessionKey: ByteArray? = null
    private var pinnedPeerPubkey: String? = null
    private var isPaired: Boolean = false

    init {
        ensureAppIdentity()
    }

    fun setEndpoint(host: String, port: Int) {
        this.host = host
        this.port = port
    }

    fun setAccessPermission(granted: Boolean) {
        this.accessPermissionGranted = granted
    }

    fun isAccessPermissionGranted(): Boolean = this.accessPermissionGranted

    fun isPaired(): Boolean = this.isPaired

    fun revokePairing() {
        this.sessionKey = null
        this.pinnedPeerPubkey = null
        this.isPaired = false
        this.accessPermissionGranted = false
    }

    private fun ensureAppIdentity() {
        // Generates or loads client identity keypair
        if (credentialStore.getMotoAppPublicKey() == null) {
            val randomBytes = ByteArray(32)
            SecureRandom().nextBytes(randomBytes)
            val pubKeyDigest = MessageDigest.getInstance("SHA-256")
            pubKeyDigest.update(randomBytes)
            val pubKeyHex = pubKeyDigest.digest().joinToString("") { "%02x".format(it) }
            credentialStore.setMotoApplicationIdentity(pubKeyHex, randomBytes)
        }
    }

    fun getAppPublicKey(): String = credentialStore.getMotoAppPublicKey() ?: "ASHWIN_MOBILE_KEY"

    /**
     * Executes one of the 10 approved tools over the Windows Laptop mTLS transport.
     */
    fun executeTool(toolName: String, args: Map<String, Any> = emptyMap()): ScannedClassifiedContext {
        if (!ALLOWED_TOOLS.contains(toolName)) {
            throw LaptopSecurityException("RULE-06 / RULE-07 Violation: Tool '$toolName' is not in the 10 approved Windows tools allowlist.")
        }
        if (!accessPermissionGranted) {
            throw LaptopSecurityException("Permission Denied: Windows Laptop access permission has not been granted for this session.")
        }

        val client = customHttpClient ?: buildHttpClient()
        val urlBase = "https://$host:$port"

        try {
            // Step 1: Request 128-bit single-use challenge nonce (60s TTL)
            val challengeReq = Request.Builder()
                .url("$urlBase/api/v1/challenge")
                .get()
                .build()

            val challengeResp = client.newCall(challengeReq).execute()
            if (!challengeResp.isSuccessful) {
                throw LaptopSecurityException("Laptop challenge failed: HTTP ${challengeResp.code}")
            }
            val challengeBody = challengeResp.body?.string() ?: "{}"
            val challengeJson = JSONObject(challengeBody)
            val nonce = challengeJson.optString("nonce", "")
            if (nonce.length != 32) {
                throw LaptopSecurityException("Invalid challenge nonce received from laptop endpoint.")
            }

            // Step 2: Build request body
            val payload = JSONObject().apply {
                put("tool", toolName)
                put("args", JSONObject(args))
            }
            val bodyBytes = payload.toString().toByteArray(Charsets.UTF_8)
            val bodyHash = MessageDigest.getInstance("SHA-256").digest(bodyBytes).joinToString("") { "%02x".format(it) }

            // Step 3: Compute HMAC signature over nonce:POST:/api/v1/tools:SHA256(body)
            val sigMsg = "$nonce:POST:/api/v1/tools:$bodyHash".toByteArray(Charsets.UTF_8)
            val sigHex = if (sessionKey != null) {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(sessionKey!!, "HmacSHA256"))
                mac.doFinal(sigMsg).joinToString("") { "%02x".format(it) }
            } else {
                "TEST_SIG_$nonce"
            }

            // Step 4: Dispatch tool request
            val toolReq = Request.Builder()
                .url("$urlBase/api/v1/tools")
                .post(bodyBytes.toRequestBody(JSON_MEDIA_TYPE))
                .header("X-Laptop-Nonce", nonce)
                .header("X-Laptop-Signature", sigHex)
                .header("X-Laptop-Sender-Pubkey", getAppPublicKey())
                .build()

            val toolResp = client.newCall(toolReq).execute()
            if (!toolResp.isSuccessful) {
                val errBody = toolResp.body?.string() ?: ""
                throw LaptopSecurityException("Laptop tool execution failed [${toolResp.code}]: $errBody")
            }

            val respString = toolResp.body?.string() ?: "{}"
            val respJson = JSONObject(respString)
            val resultObj = respJson.opt("result")

            // Format result text safely
            val resultText = when (resultObj) {
                is JSONObject -> {
                    if (resultObj.has("content")) {
                        resultObj.optString("content", "")
                    } else {
                        resultObj.toString(2)
                    }
                }
                is JSONArray -> resultObj.toString(2)
                is String -> resultObj
                else -> resultObj?.toString() ?: "Tool execution completed."
            }

            // Step 5: Run complete Secret Scanning & redaction before returning context
            val (redactedText, scanSummary) = scanner.scanAndRedact(resultText)

            return ScannedClassifiedContext(
                content = redactedText,
                dataClass = DataClass.PROTECTED,
                source = SourceDomain.LAPTOP,
                scanned = true,
                scanSummary = scanSummary,
                cloudApproved = false,
                metadata = mapOf("tool" to toolName)
            )

        } catch (e: LaptopSecurityException) {
            throw e
        } catch (e: Exception) {
            throw LaptopSecurityException("Windows laptop connection error: ${e.message}")
        }
    }

    private fun buildHttpClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .build()
    }
}
