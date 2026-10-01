package org.ashwin.core

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class ProvisioningException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class ProvisioningResult(
    val success: Boolean,
    val packageId: String,
    val endpointHost: String,
    val endpointPort: Int,
    val message: String
)

/**
 * ASHWIN Secure Provisioning Engine (Phase 2, Section 7, Section 12, RULE-02).
 *
 * Implements:
 * 1. ASHWIN-PROV-1.0 encrypted package format parser (PBKDF2-HMAC-SHA256 600,000 iter + AES-256-GCM).
 * 2. Rate limiting & backoff protection on PIN entry (Max 5 attempts).
 * 3. Anti-replay verification with atomic CredentialStore package registration.
 * 4. Strict cryptographic certificate/keypair validation:
 *    - X.509 validity periods
 *    - RSA key algorithm and min 2048-bit size
 *    - Client certificate public key matches client private key
 *    - Certificate SHA-256 fingerprint verification against authenticated metadata
 *    - Cryptographic server identity anchor preservation.
 */
class ProvisioningEngine(
    private val credentialStore: CredentialStore
) {
    companion object {
        val MAGIC = byteArrayOf(0x41, 0x53, 0x48, 0x57, 0x49, 0x4E, 0x50, 0x52) // "ASHWINPR"
        val FORMAT_VERSION_1 = byteArrayOf(0x00, 0x01)
        const val PBKDF2_ITERATIONS = 600_000
        const val MAX_FAILED_ATTEMPTS = 5
        private val BACKOFF_MS = longArrayOf(0, 2000, 5000, 15000)
    }

    private var failedAttempts: Int = 0
    private var lastAttemptTimestamp: Long = 0L

    // =========================================================================
    // Rate Limiter
    // =========================================================================

    @Synchronized
    private fun checkRateLimit() {
        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            throw ProvisioningException("Provisioning locked: Exceeded maximum allowed Setup PIN attempts ($MAX_FAILED_ATTEMPTS). Generate a new package.")
        }
        val now = System.currentTimeMillis()
        if (failedAttempts > 0) {
            val backoffIdx = (failedAttempts - 1).coerceAtMost(BACKOFF_MS.size - 1)
            val requiredDelay = BACKOFF_MS[backoffIdx]
            val elapsed = now - lastAttemptTimestamp
            if (elapsed < requiredDelay) {
                val remaining = requiredDelay - elapsed
                throw ProvisioningException("Rate limit active: Please wait ${remaining / 1000 + 1}s before retrying.")
            }
        }
    }

    @Synchronized
    private fun recordFailure() {
        failedAttempts++
        lastAttemptTimestamp = System.currentTimeMillis()
    }

    @Synchronized
    private fun recordSuccess() {
        failedAttempts = 0
        lastAttemptTimestamp = 0L
    }

    // =========================================================================
    // Provisioning Ingestion & Strict Validation
    // =========================================================================

    fun ingestPackage(
        packageBytes: ByteArray,
        pinChars: CharArray,
        currentTimeSeconds: Long? = null
    ): ProvisioningResult {
        checkRateLimit()

        val minHeaderLen = 8 + 2 + 32 + 12 + 16 // 70 bytes minimum
        if (packageBytes.size < minHeaderLen) {
            recordFailure()
            throw ProvisioningException("Invalid package: Truncated binary header.")
        }

        // 1. Verify Magic & Version
        for (i in 0 until 8) {
            if (packageBytes[i] != MAGIC[i]) {
                recordFailure()
                throw ProvisioningException("Invalid package: Missing ASHWINPR magic header.")
            }
        }
        if (packageBytes[8] != FORMAT_VERSION_1[0] || packageBytes[9] != FORMAT_VERSION_1[1]) {
            recordFailure()
            throw ProvisioningException("Unsupported package format version.")
        }

        val salt = packageBytes.copyOfRange(10, 42)
        val iv = packageBytes.copyOfRange(42, 54)
        val ciphertextAndTag = packageBytes.copyOfRange(54, packageBytes.size)

        // 2. Derive Key via PBKDF2-HMAC-SHA256 (600,000 iterations)
        val keyBytes: ByteArray
        try {
            val spec = PBEKeySpec(pinChars, salt, PBKDF2_ITERATIONS, 256)
            val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            keyBytes = skf.generateSecret(spec).encoded
        } catch (e: Exception) {
            recordFailure()
            throw ProvisioningException("KDF key derivation failed: ${e.message}", e)
        } finally {
            // Immediate zeroing of PIN characters
            Arrays.fill(pinChars, '\u0000')
        }

        // 3. AES-256-GCM Decryption with Authenticated Additional Data (AAD)
        val decryptedBytes: ByteArray
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            val secretKey = SecretKeySpec(keyBytes, "AES")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
            // AAD binds MAGIC + VERSION
            val aad = byteArrayOf(
                MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], MAGIC[4], MAGIC[5], MAGIC[6], MAGIC[7],
                FORMAT_VERSION_1[0], FORMAT_VERSION_1[1]
            )
            cipher.updateAAD(aad)
            decryptedBytes = cipher.doFinal(ciphertextAndTag)
        } catch (e: Exception) {
            recordFailure()
            throw ProvisioningException("Decryption failed: Incorrect Setup PIN or corrupted package.", e)
        } finally {
            Arrays.fill(keyBytes, 0.toByte())
        }

        // 4. Parse JSON Payload
        val payloadStr = String(decryptedBytes, StandardCharsets.UTF_8)
        val json = try {
            JSONObject(payloadStr)
        } catch (e: Exception) {
            recordFailure()
            throw ProvisioningException("Malformed JSON payload inside package.", e)
        }

        val metadata = json.optJSONObject("metadata")
            ?: throw ProvisioningException("Missing metadata in package payload.")
        val credentials = json.optJSONObject("credentials")
            ?: throw ProvisioningException("Missing credentials in package payload.")

        val packageId = metadata.optString("package_id")
        if (packageId.isBlank()) {
            recordFailure()
            throw ProvisioningException("Missing package_id in package metadata.")
        }

        // 5. Anti-Replay Verification
        if (credentialStore.isPackageConsumed(packageId)) {
            recordFailure()
            throw ProvisioningException("Security Rejection: Package $packageId has already been consumed.")
        }

        // 6. Expiration Verification
        val nowSec = currentTimeSeconds ?: (System.currentTimeMillis() / 1000L)
        val expiresAt = metadata.optLong("expires_at", 0L)
        if (nowSec > expiresAt) {
            recordFailure()
            throw ProvisioningException("Security Rejection: Provisioning package expired at $expiresAt (current $nowSec).")
        }

        val caPem = credentials.optString("ca_cert_pem")
        val clientCertPem = credentials.optString("client_cert_pem")
        val clientKeyPem = credentials.optString("client_key_pem")

        // 7. Strict Certificate & Keypair Validation
        val (caCert, clientCert, _) = validateCredentials(caPem, clientCertPem, clientKeyPem)

        // 8. Verify Fingerprints against Authenticated Metadata
        val expectedCaFp = metadata.optString("ca_cert_fingerprint_sha256")
        if (expectedCaFp.isNotBlank()) {
            val actualCaFp = computeFingerprint(caCert)
            if (actualCaFp != expectedCaFp) {
                recordFailure()
                throw ProvisioningException("CA certificate fingerprint mismatch against authenticated metadata.")
            }
        }

        val expectedClientFp = metadata.optString("client_cert_fingerprint_sha256")
        if (expectedClientFp.isNotBlank()) {
            val actualClientFp = computeFingerprint(clientCert)
            if (actualClientFp != expectedClientFp) {
                recordFailure()
                throw ProvisioningException("Client certificate fingerprint mismatch against authenticated metadata.")
            }
        }

        // 9. Preserved Cryptographic Identity & Endpoint Config
        val intendedEndpointId = metadata.optString("intended_endpoint_id", "MOTO-G3-01")
        val host = metadata.optString("endpoint_host", EndpointConfig.DEFAULT_MOTO_HOST)
        val port = metadata.optInt("endpoint_port", EndpointConfig.DEFAULT_MOTO_PORT)
        val useTls = metadata.optBoolean("endpoint_use_tls", true)
        val endpointConfig = EndpointConfig(host = host, port = port, useTls = useTls)

        // 10. Atomic Commit to CredentialStore
        credentialStore.commitProvisionedCredentials(
            packageId = packageId,
            caPem = caPem,
            clientCertPem = clientCertPem,
            clientKeyPem = clientKeyPem,
            config = endpointConfig
        )

        recordSuccess()

        return ProvisioningResult(
            success = true,
            packageId = packageId,
            endpointHost = host,
            endpointPort = port,
            message = "Moto identity provisioned successfully for $intendedEndpointId."
        )
    }

    // =========================================================================
    // Strict Cryptographic Validation Helpers
    // =========================================================================

    private fun validateCredentials(
        caPem: String,
        clientCertPem: String,
        clientKeyPem: String
    ): Triple<X509Certificate, X509Certificate, PrivateKey> {
        if (caPem.isBlank() || clientCertPem.isBlank() || clientKeyPem.isBlank()) {
            throw ProvisioningException("Incomplete certificate or key material in package.")
        }

        // 1. Parse CA Certificate & Check Validity
        val caCert = parseCert(caPem, "CA Certificate")
        try {
            caCert.checkValidity()
        } catch (e: Exception) {
            throw ProvisioningException("CA certificate is not valid at current time: ${e.message}", e)
        }

        // 2. Parse Client Certificate & Check Validity
        val clientCert = parseCert(clientCertPem, "Client Certificate")
        try {
            clientCert.checkValidity()
        } catch (e: Exception) {
            throw ProvisioningException("Client certificate is not valid at current time: ${e.message}", e)
        }

        // 3. Parse Client Private Key
        val clientKey = parsePrivateKey(clientKeyPem)

        // 4. Algorithm & Size Validation (Require RSA >= 2048)
        if (clientKey !is RSAKey) {
            throw ProvisioningException("Expected RSA client private key algorithm.")
        }
        val keyBitLength = clientKey.modulus.bitLength()
        if (keyBitLength < 2048) {
            throw ProvisioningException("Insecure key size: RSA $keyBitLength is less than required 2048 bits.")
        }

        // 5. Verify Client Certificate Public Key Matches Client Private Key
        val testData = "ASHWIN_KEYPAIR_VALIDATION".toByteArray(StandardCharsets.UTF_8)
        try {
            val signer = Signature.getInstance("SHA256withRSA")
            signer.initSign(clientKey)
            signer.update(testData)
            val signatureBytes = signer.sign()

            val verifier = Signature.getInstance("SHA256withRSA")
            verifier.initVerify(clientCert.publicKey)
            verifier.update(testData)
            if (!verifier.verify(signatureBytes)) {
                throw ProvisioningException("Cryptographic mismatch: Client certificate public key does not match private key.")
            }
        } catch (e: ProvisioningException) {
            throw e
        } catch (e: Exception) {
            throw ProvisioningException("Keypair verification failed: ${e.message}", e)
        }

        return Triple(caCert, clientCert, clientKey)
    }

    private fun parseCert(pem: String, label: String): X509Certificate {
        try {
            val clean = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\\s".toRegex(), "")
            val der = Base64.decode(clean, Base64.DEFAULT)
            val cf = CertificateFactory.getInstance("X.509")
            return cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        } catch (e: Exception) {
            throw ProvisioningException("Failed to parse $label: ${e.message}", e)
        }
    }

    private fun parsePrivateKey(pem: String): PrivateKey {
        try {
            val clean = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("\\s".toRegex(), "")
            val der = Base64.decode(clean, Base64.DEFAULT)
            val spec = PKCS8EncodedKeySpec(der)
            val kf = KeyFactory.getInstance("RSA")
            return kf.generatePrivate(spec)
        } catch (e: Exception) {
            throw ProvisioningException("Failed to parse client private key: ${e.message}", e)
        }
    }

    private fun computeFingerprint(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(cert.encoded)
        val sb = StringBuilder()
        for (b in hash) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }
}
