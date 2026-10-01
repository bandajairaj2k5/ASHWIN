package org.ashwin.core

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class MotoSecurityException(message: String) : Exception(message)
class MotoFeasibilityException(message: String) : Exception(message)

data class PairResponse(
    val status: String,
    val sas: String,
    val serverPubKey: String
)

/**
 * ASHWIN Moto G3 Storage Client (Phase 2, Section 6.3, Section 7.4, Section 10, T-57).
 *
 * Implements:
 * 1. TLS 1.3 mTLS client transport using CredentialStore client certificates and pinned CA.
 * 2. Exact V0.1 challenge-response authentication with 128-bit single-use nonce.
 * 3. 6-digit Short Authentication String (SAS) derivation and HMAC-SHA256 session key derivation.
 * 4. HMAC-SHA256 request signing over method, path, nonce, and SHA-256 body hash.
 * 5. Complete bounded buffering (<= 5 MB), TextExtractor validation, SecretScanner redaction,
 *    and LocationFormatter sanitization into ScannedClassifiedContext (PROTECTED class).
 */
class MotoStorageClient(
    val credentialStore: CredentialStore,
    private val scanner: SecretScanner = SecretScanner(),
    private var customHttpClient: OkHttpClient? = null
) {
    companion object {
        const val MAX_BUFFER_SIZE = 5 * 1024 * 1024 // 5 MB hard limit
        private const val SAS_SALT = "ASHWIN_SAS_SALT"
        private const val SESSION_SALT = "ASHWIN_MOTO_MTLS_SECRET"
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    }

    private var accessPermissionGranted: Boolean = false
    private var feasibilityPassed: Boolean = false

    init {
        ensureAppIdentity()
    }

    // =========================================================================
    // Security & Permission State
    // =========================================================================

    fun setAccessPermission(granted: Boolean) {
        this.accessPermissionGranted = granted
    }

    fun isAccessPermissionGranted(): Boolean = this.accessPermissionGranted

    fun runFeasibilityGate(tlsSupported: Boolean = true, cryptoSupported: Boolean = true, backgroundOk: Boolean = true): Boolean {
        if (tlsSupported && cryptoSupported && backgroundOk) {
            feasibilityPassed = true
            return true
        }
        feasibilityPassed = false
        throw MotoFeasibilityException("Section 7.4 Gate Failure: Moto G3 transport requirements not met.")
    }

    fun isPaired(): Boolean = credentialStore.isMotoPaired()

    fun revokePairing() {
        credentialStore.revokeMotoPairing()
    }

    // =========================================================================
    // Cryptographic Helpers & Identity
    // =========================================================================

    private fun ensureAppIdentity() {
        if (credentialStore.getMotoAppPublicKey() == null || credentialStore.getMotoAppPrivateKey() == null) {
            val randomBytes = ByteArray(32)
            SecureRandom().nextBytes(randomBytes)
            val pubKeyDigest = MessageDigest.getInstance("SHA-256")
            pubKeyDigest.update(randomBytes)
            pubKeyDigest.update("_pub".toByteArray(StandardCharsets.UTF_8))
            val pubKeyHex = bytesToHex(pubKeyDigest.digest())
            credentialStore.setMotoApplicationIdentity(pubKeyHex, randomBytes)
        }
    }

    fun computeSasCode(peerPubKey: String): String {
        val clientPub = credentialStore.getMotoAppPublicKey()
            ?: throw MotoSecurityException("Client public key not initialized.")
        val keys = listOf(clientPub, peerPubKey).sorted()
        val combined = "${keys[0]}:${keys[1]}".toByteArray(StandardCharsets.UTF_8)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(SAS_SALT.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        val h = bytesToHex(mac.doFinal(combined))
        val num = h.substring(0, 8).toLong(16) % 1_000_000
        return String.format(Locale.US, "%06d", num)
    }

    private fun deriveSessionKey(peerPubKey: String): ByteArray {
        val clientPub = credentialStore.getMotoAppPublicKey()
            ?: throw MotoSecurityException("Client public key not initialized.")
        val keys = listOf(clientPub, peerPubKey).sorted()
        val combined = "${keys[0]}:${keys[1]}".toByteArray(StandardCharsets.UTF_8)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(SESSION_SALT.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(combined)
    }

    private fun signPayload(nonce: String, method: String, path: String, body: ByteArray): String {
        val sessionKey = credentialStore.getMotoSessionKey()
            ?: throw MotoSecurityException("Cannot sign: Device is not paired or session key missing.")
        val bodySha256 = bytesToHex(MessageDigest.getInstance("SHA-256").digest(body))
        val message = "$nonce:$method:$path:$bodySha256".toByteArray(StandardCharsets.UTF_8)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sessionKey, "HmacSHA256"))
        return bytesToHex(mac.doFinal(message))
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = java.lang.StringBuilder()
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    // =========================================================================
    // HTTP & TLS 1.3 Transport Client
    // =========================================================================

    private fun getOrCreateHttpClient(): OkHttpClient {
        customHttpClient?.let { return it }

        val endpointConfig = credentialStore.getEndpointConfig()
        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)

        if (endpointConfig.useTls) {
            val sslContext = buildSslContext()
            val trustManager = buildTrustManager()
            builder.sslSocketFactory(sslContext.socketFactory, trustManager)
            builder.hostnameVerifier { _, session ->
                val peerCerts = session.peerCertificates
                if (peerCerts.isNotEmpty() && peerCerts[0] is X509Certificate) {
                    val x509 = peerCerts[0] as X509Certificate
                    x509.subjectX500Principal.name.contains("MOTO-G3-STORAGE-ENDPOINT") ||
                            x509.subjectX500Principal.name.contains(endpointConfig.host)
                } else {
                    false
                }
            }
        }

        return builder.build()
    }

    private fun buildTrustManager(): X509TrustManager {
        val caCert = credentialStore.getParsedCaCertificate()
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            if (caCert != null) {
                setCertificateEntry("moto_ca", caCert)
            }
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(trustStore)
        for (tm in tmf.trustManagers) {
            if (tm is X509TrustManager) return tm
        }
        throw MotoSecurityException("No X509TrustManager found.")
    }

    private fun buildSslContext(): SSLContext {
        val clientCert = credentialStore.getParsedCertificate()
        val clientKey = credentialStore.getParsedPrivateKey()
        val caCert = credentialStore.getParsedCaCertificate()

        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            if (clientCert != null && clientKey != null) {
                val chain = if (caCert != null) arrayOf(clientCert, caCert) else arrayOf(clientCert)
                setKeyEntry("client_key", clientKey, "ashwin_pwd".toCharArray(), chain)
            }
        }

        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(keyStore, "ashwin_pwd".toCharArray())

        val trustManager = buildTrustManager()
        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(kmf.keyManagers, arrayOf<TrustManager>(trustManager), SecureRandom())
        return sslContext
    }

    // =========================================================================
    // Request Dispatch Pipeline
    // =========================================================================

    private fun executeAuthenticatedRequest(method: String, path: String, body: ByteArray): Pair<Int, ByteArray> {
        if (!isPaired()) {
            throw MotoSecurityException("Moto device is not paired.")
        }

        val endpointConfig = credentialStore.getEndpointConfig()
        val baseUrl = endpointConfig.baseUrl.trimEnd('/')

        // Step 1: Pre-flight challenge request
        val challengeNonce = fetchChallenge()

        // Step 2: Sign request
        val signature = signPayload(challengeNonce, method, path, body)
        val clientPubKey = credentialStore.getMotoAppPublicKey()
            ?: throw MotoSecurityException("Client public key is missing.")

        // Step 3: Build HTTP request
        val client = getOrCreateHttpClient()
        val url = "$baseUrl$path"
        val requestBody = body.toRequestBody(JSON_MEDIA_TYPE)

        val request = Request.Builder()
            .url(url)
            .method(method, requestBody)
            .addHeader("X-Moto-Nonce", challengeNonce)
            .addHeader("X-Moto-Signature", signature)
            .addHeader("X-Client-PubKey", clientPubKey)
            .build()

        val response: Response = try {
            client.newCall(request).execute()
        } catch (e: Exception) {
            throw MotoSecurityException("Transport error during request to $path: ${e.message}")
        }

        val respBytes = response.body?.bytes() ?: ByteArray(0)
        return Pair(response.code, respBytes)
    }

    fun fetchChallenge(): String {
        val endpointConfig = credentialStore.getEndpointConfig()
        val url = "${endpointConfig.baseUrl.trimEnd('/')}/storage/v1/challenge"
        val client = getOrCreateHttpClient()

        val emptyBody = "".toRequestBody(JSON_MEDIA_TYPE)
        val request = Request.Builder().url(url).post(emptyBody).build()

        val response = try {
            client.newCall(request).execute()
        } catch (e: Exception) {
            throw MotoSecurityException("Failed to fetch challenge nonce: ${e.message}")
        }

        if (!response.isSuccessful) {
            throw MotoSecurityException("Challenge request failed with code ${response.code}")
        }

        val bodyStr = response.body?.string() ?: ""
        val json = JSONObject(bodyStr)
        return json.getString("nonce")
    }

    fun pair(userSasConfirmed: Boolean): PairResponse {
        val endpointConfig = credentialStore.getEndpointConfig()
        val url = "${endpointConfig.baseUrl.trimEnd('/')}/storage/v1/pair"
        val client = getOrCreateHttpClient()

        val clientPub = credentialStore.getMotoAppPublicKey()
            ?: throw MotoSecurityException("Client public key missing.")

        val reqJson = JSONObject().apply {
            put("client_pubkey", clientPub)
            put("user_sas_confirmed", userSasConfirmed)
        }

        val request = Request.Builder()
            .url(url)
            .post(reqJson.toString().toByteArray(StandardCharsets.UTF_8).toRequestBody(JSON_MEDIA_TYPE))
            .build()

        val response = try {
            client.newCall(request).execute()
        } catch (e: Exception) {
            throw MotoSecurityException("Failed to execute pair request: ${e.message}")
        }

        if (!response.isSuccessful) {
            throw MotoSecurityException("Pairing failed with status ${response.code}")
        }

        val bodyStr = response.body?.string() ?: ""
        val json = JSONObject(bodyStr)
        val status = json.getString("status")
        val sas = json.getString("sas")
        val serverPub = json.getString("server_pubkey")

        if (userSasConfirmed && status == "PAIRED") {
            val sessionKey = deriveSessionKey(serverPub)
            credentialStore.completeMotoPairing(serverPub, sessionKey)
        }

        return PairResponse(status = status, sas = sas, serverPubKey = serverPub)
    }

    // =========================================================================
    // Moto Storage Capabilities
    // =========================================================================

    fun listFiles(subfolder: String = ""): ScannedClassifiedContext {
        if (!isPaired()) {
            throw MotoSecurityException("Moto device is not paired.")
        }
        if (!accessPermissionGranted) {
            throw MotoSecurityException("Permission Denied: Access permission check failed before retrieving Moto contents.")
        }

        val reqBody = JSONObject().put("subfolder", subfolder).toString().toByteArray(StandardCharsets.UTF_8)
        val (statusCode, respBytes) = executeAuthenticatedRequest("POST", "/storage/v1/list", reqBody)

        if (statusCode != 200) {
            throw MotoSecurityException("List failed with code $statusCode: ${String(respBytes, StandardCharsets.UTF_8)}")
        }

        if (respBytes.size > MAX_BUFFER_SIZE) {
            throw MotoSecurityException("List response exceeded 5 MB limit.")
        }

        val json = JSONObject(String(respBytes, StandardCharsets.UTF_8))
        val itemsArray: JSONArray = json.optJSONArray("items") ?: JSONArray()
        val fileNames = mutableListOf<String>()
        for (i in 0 until itemsArray.length()) {
            val item = itemsArray.getJSONObject(i)
            fileNames.add(item.optString("name"))
        }

        val fileListStr = fileNames.joinToString(", ")
        val (redactedText, scanSummary, _) = scanner.scanAndRedact(fileListStr)

        if (scanSummary["healthy"] != true) {
            throw RouterGateException("Secret scan failed for list contents.")
        }

        val location = LocationFormatter.formatForModel("MOTO_STORAGE", if (subfolder.isBlank()) "root" else subfolder)

        return ScannedClassifiedContext(
            content = redactedText,
            dataClass = DataClass.PROTECTED,
            source = SourceDomain.MOTO_STORAGE,
            cloudApproved = false,
            scanned = true,
            scanSummary = scanSummary,
            metadata = mapOf(
                "name" to (if (subfolder.isBlank()) "root" else subfolder),
                "item_count" to fileNames.size,
                "scope_label" to "MOTO_STORAGE",
                "location_for_model" to location
            )
        )
    }

    fun searchFiles(query: String, category: String = ""): ScannedClassifiedContext {
        if (!isPaired()) {
            throw MotoSecurityException("Moto device is not paired.")
        }
        if (!accessPermissionGranted) {
            throw MotoSecurityException("Permission Denied: Access permission check failed before searching Moto storage.")
        }

        val reqBody = JSONObject()
            .put("query", query)
            .put("category", category)
            .toString()
            .toByteArray(StandardCharsets.UTF_8)

        val (statusCode, respBytes) = executeAuthenticatedRequest("POST", "/storage/v1/search", reqBody)

        if (statusCode != 200) {
            throw MotoSecurityException("Search failed with code $statusCode: ${String(respBytes, StandardCharsets.UTF_8)}")
        }

        if (respBytes.size > MAX_BUFFER_SIZE) {
            throw MotoSecurityException("Search response exceeded 5 MB limit.")
        }

        val json = JSONObject(String(respBytes, StandardCharsets.UTF_8))
        val resultsArray: JSONArray = json.optJSONArray("results") ?: JSONArray()
        val matches = mutableListOf<String>()
        for (i in 0 until resultsArray.length()) {
            val item = resultsArray.getJSONObject(i)
            val relPath = item.optString("path", item.optString("name"))
            val safeLocation = LocationFormatter.formatForModel("MOTO_STORAGE", relPath)
            matches.add("${item.optString("name")} ($safeLocation)")
        }

        val resultsSummary = matches.joinToString("\n")
        val (redactedText, scanSummary, _) = scanner.scanAndRedact(resultsSummary)

        if (scanSummary["healthy"] != true) {
            throw RouterGateException("Secret scan failed for search results.")
        }

        return ScannedClassifiedContext(
            content = redactedText,
            dataClass = DataClass.PROTECTED,
            source = SourceDomain.MOTO_STORAGE,
            cloudApproved = false,
            scanned = true,
            scanSummary = scanSummary,
            metadata = mapOf(
                "query" to query,
                "result_count" to matches.size,
                "scope_label" to "MOTO_STORAGE"
            )
        )
    }

    fun readFile(relPath: String): ScannedClassifiedContext {
        // Step 1: Verification of Pairing and Access Permission FIRST (T-57)
        if (!isPaired()) {
            throw MotoSecurityException("Moto device is not paired.")
        }
        if (!accessPermissionGranted) {
            throw MotoSecurityException("Access permission denied for Moto storage.")
        }

        val reqBody = JSONObject().put("file_path", relPath).toString().toByteArray(StandardCharsets.UTF_8)
        val (statusCode, respBytes) = executeAuthenticatedRequest("POST", "/storage/v1/read", reqBody)

        when (statusCode) {
            413 -> throw MotoSecurityException("Moto file size exceeds 5 MB limit. AI delivery denied.")
            403 -> throw MotoSecurityException("Access Forbidden: Path outside ASHWIN_STORAGE.")
            404 -> throw MotoSecurityException("File '$relPath' not found in ASHWIN_STORAGE.")
            200 -> {}
            else -> throw MotoSecurityException("Read failed with code $statusCode: ${String(respBytes, StandardCharsets.UTF_8)}")
        }

        // Step 2: Bounded complete buffering check (5 MB max) on client
        if (respBytes.size > MAX_BUFFER_SIZE) {
            throw MotoSecurityException("Moto file size ${respBytes.size} exceeds 5 MB limit. AI delivery denied.")
        }

        // Step 3: Text extraction & validation
        val extractedText = TextExtractor.validateAndExtractTxt(respBytes)

        // Step 4: Secret scan & redaction (RULE-09)
        val (redactedText, scanSummary, _) = scanner.scanAndRedact(extractedText)

        if (scanSummary["healthy"] != true) {
            throw RouterGateException("Moto file secret scan failed.")
        }

        // Step 5: Format location (RULE-15: scope label + name)
        val modelLocation = LocationFormatter.formatForModel("MOTO_STORAGE", File(relPath).name)

        // Step 6: Wrap in ScannedClassifiedContext (RULE-04, PROTECTED class per Section 4.3)
        return ScannedClassifiedContext(
            content = redactedText,
            dataClass = DataClass.PROTECTED,
            source = SourceDomain.MOTO_STORAGE,
            cloudApproved = false,
            scanned = true,
            scanSummary = scanSummary,
            metadata = mapOf(
                "name" to File(relPath).name,
                "scope_label" to "MOTO_STORAGE",
                "location_for_model" to modelLocation
            )
        )
    }
}
