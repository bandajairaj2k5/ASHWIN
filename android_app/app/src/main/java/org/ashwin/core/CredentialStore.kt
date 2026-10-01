package org.ashwin.core

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * ASHWIN Credential & Identity Store (Phase 1, Section 7, Section 12, RULE-02, RULE-12).
 *
 * Security Architecture:
 * 1. Cloud API Keys and Moto Session Keys are encrypted at rest using Android KeyStore master keys (AES-256-GCM).
 * 2. Transport client RSA keys and X.509 certificates are imported and managed via KeyStore / PKCS#8 specs.
 * 3. Raw credentials are never logged, never exposed to AI model prompts, and never accessible to UI views.
 * 4. Revocation immediately purges active memory keys and overwrites encrypted persistence.
 */
class CredentialStore(private val context: Context? = null) {

    private val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private val MASTER_KEY_ALIAS = "ASHWIN_CORE_MASTER_KEY"
    private val PREFS_NAME = "ashwin_secure_credentials"

    // In-memory active security state
    private var cloudApiKey: String? = null
    private var motoCaCertPem: String? = null
    private var motoTransportCertPem: String? = null
    private var motoTransportKeyPem: String? = null
    private var motoAppPublicKey: String? = null
    private var motoAppPrivateKey: ByteArray? = null
    private var motoPinnedPeerPublicKey: String? = null
    private var motoSessionKey: ByteArray? = null
    private var motoIsPaired: Boolean = false
    private var endpointConfig: EndpointConfig = EndpointConfig()
    private val consumedPackageIds = mutableSetOf<String>()

    init {
        loadEncryptedCredentials()
    }

    // =========================================================================
    // Cloud AI Credential Lifecycle
    // =========================================================================

    fun setCloudApiKey(apiKey: String) {
        require(apiKey.isNotBlank()) { "API key cannot be blank" }
        this.cloudApiKey = apiKey.trim()
        persistEncryptedString("cloud_api_key", this.cloudApiKey)
    }

    fun getCloudApiKey(): String? {
        return this.cloudApiKey
    }

    fun hasCloudApiKey(): Boolean {
        return !this.cloudApiKey.isNullOrBlank()
    }

    fun clearCloudApiKey() {
        this.cloudApiKey = null
        removeEncryptedEntry("cloud_api_key")
    }

    // =========================================================================
    // Endpoint Configuration Lifecycle
    // =========================================================================

    fun setEndpointConfig(config: EndpointConfig) {
        this.endpointConfig = config
        persistEncryptedString("endpoint_host", config.host)
        persistEncryptedString("endpoint_port", config.port.toString())
        persistEncryptedString("endpoint_use_tls", config.useTls.toString())
    }

    fun getEndpointConfig(): EndpointConfig {
        return this.endpointConfig
    }

    // =========================================================================
    // Moto Client Transport Identity (X.509 + RSA Private Key)
    // =========================================================================

    fun setMotoTransportIdentity(certPem: String, keyPem: String) {
        require(certPem.isNotBlank() && keyPem.isNotBlank()) { "Certificate and Key PEM cannot be blank" }
        this.motoTransportCertPem = certPem
        this.motoTransportKeyPem = keyPem
        persistEncryptedString("moto_cert_pem", certPem)
        persistEncryptedString("moto_key_pem", keyPem)
    }

    fun setMotoCaCertPem(caPem: String) {
        require(caPem.isNotBlank()) { "CA Certificate PEM cannot be blank" }
        this.motoCaCertPem = caPem
        persistEncryptedString("moto_ca_pem", caPem)
    }

    fun getMotoCaCertPem(): String? = this.motoCaCertPem

    fun getMotoTransportCertPem(): String? = this.motoTransportCertPem
    fun getMotoTransportKeyPem(): String? = this.motoTransportKeyPem

    /**
     * Parses the PKCS#8 PEM private key into an RSA PrivateKey instance.
     */
    fun getParsedPrivateKey(): PrivateKey? {
        val pem = motoTransportKeyPem ?: return null
        val cleanKey = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replace("\\s".toRegex(), "")
        val keyBytes = Base64.decode(cleanKey, Base64.DEFAULT)
        val spec = PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(spec)
    }

    /**
     * Parses the X.509 Certificate PEM.
     */
    fun getParsedCertificate(): X509Certificate? {
        val pem = motoTransportCertPem ?: return null
        return parseCertFromPem(pem)
    }

    /**
     * Parses the X.509 CA Certificate PEM.
     */
    fun getParsedCaCertificate(): X509Certificate? {
        val pem = motoCaCertPem ?: return null
        return parseCertFromPem(pem)
    }

    private fun parseCertFromPem(pem: String): X509Certificate? {
        val cleanCert = pem
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\\s".toRegex(), "")
        val certBytes = Base64.decode(cleanCert, Base64.DEFAULT)
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
    }

    // =========================================================================
    // Moto Application Layer Identity & Session Signing
    // =========================================================================

    fun setMotoApplicationIdentity(publicKeyHex: String, privateKeyBytes: ByteArray) {
        this.motoAppPublicKey = publicKeyHex
        this.motoAppPrivateKey = privateKeyBytes.copyOf()
        persistEncryptedString("moto_app_pubkey", publicKeyHex)
        persistEncryptedBytes("moto_app_privkey", privateKeyBytes)
    }

    fun getMotoAppPublicKey(): String? = this.motoAppPublicKey
    fun getMotoAppPrivateKey(): ByteArray? = this.motoAppPrivateKey?.copyOf()

    fun completeMotoPairing(pinnedPeerPublicKey: String, sessionKey: ByteArray) {
        this.motoPinnedPeerPublicKey = pinnedPeerPublicKey
        this.motoSessionKey = sessionKey.copyOf()
        this.motoIsPaired = true
        persistEncryptedString("moto_peer_pubkey", pinnedPeerPublicKey)
        persistEncryptedBytes("moto_session_key", sessionKey)
        persistEncryptedString("moto_paired", "true")
    }

    fun isMotoPaired(): Boolean = this.motoIsPaired
    fun getMotoPinnedPeerPublicKey(): String? = this.motoPinnedPeerPublicKey
    fun getMotoSessionKey(): ByteArray? = this.motoSessionKey?.copyOf()

    /**
     * Revocation: Immediately purges all pairing secrets, keys, and authorization state.
     */
    fun revokeMotoPairing() {
        this.motoPinnedPeerPublicKey = null
        this.motoSessionKey = null
        this.motoIsPaired = false
        removeEncryptedEntry("moto_peer_pubkey")
        removeEncryptedEntry("moto_session_key")
        removeEncryptedEntry("moto_paired")
    }

    // =========================================================================
    // Provisioning & Atomic Batch Commit (Section 7, Section 12)
    // =========================================================================

    fun isPackageConsumed(packageId: String): Boolean = consumedPackageIds.contains(packageId)
    fun getConsumedPackageIds(): Set<String> = consumedPackageIds.toSet()

    /**
     * Atomically commits provisioned credentials and registers the consumed package ID
     * in a single batch update to eliminate partial provisioning states.
     */
    fun commitProvisionedCredentials(
        packageId: String,
        caPem: String,
        clientCertPem: String,
        clientKeyPem: String,
        config: EndpointConfig
    ) {
        require(packageId.isNotBlank()) { "packageId cannot be blank" }
        require(caPem.isNotBlank()) { "caPem cannot be blank" }
        require(clientCertPem.isNotBlank()) { "clientCertPem cannot be blank" }
        require(clientKeyPem.isNotBlank()) { "clientKeyPem cannot be blank" }

        // Update in-memory state
        this.motoCaCertPem = caPem
        this.motoTransportCertPem = clientCertPem
        this.motoTransportKeyPem = clientKeyPem
        this.endpointConfig = config
        this.consumedPackageIds.add(packageId)

        // Batch encrypted persistence
        val prefs = getPrefs()
        if (prefs != null) {
            val editor = prefs.edit()
            fun encryptAndPut(k: String, v: String) {
                val enc = encryptData(v.toByteArray(Charsets.UTF_8))
                if (enc != null) {
                    editor.putString("${k}_iv", Base64.encodeToString(enc.first, Base64.NO_WRAP))
                    editor.putString("${k}_data", Base64.encodeToString(enc.second, Base64.NO_WRAP))
                }
            }
            encryptAndPut("moto_ca_pem", caPem)
            encryptAndPut("moto_cert_pem", clientCertPem)
            encryptAndPut("moto_key_pem", clientKeyPem)
            encryptAndPut("endpoint_host", config.host)
            encryptAndPut("endpoint_port", config.port.toString())
            encryptAndPut("endpoint_use_tls", config.useTls.toString())
            encryptAndPut("consumed_package_ids", consumedPackageIds.joinToString(","))
            editor.apply()
        }
    }

    fun clearAll() {
        clearCloudApiKey()
        revokeMotoPairing()
        this.motoCaCertPem = null
        this.motoTransportCertPem = null
        this.motoTransportKeyPem = null
        this.motoAppPublicKey = null
        this.motoAppPrivateKey = null
        this.consumedPackageIds.clear()
        if (context != null) {
            getPrefs()?.edit()?.clear()?.apply()
        }
    }

    // =========================================================================
    // Android KeyStore AES-256-GCM Encryption Engine
    // =========================================================================

    private fun getPrefs(): SharedPreferences? {
        return context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private fun getOrCreateMasterKey(): SecretKey? {
        if (context == null) return null
        try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)
            if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
                val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
                val spec = KeyGenParameterSpec.Builder(
                    MASTER_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGen.init(spec)
                return keyGen.generateKey()
            }
            return (keyStore.getEntry(MASTER_KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        } catch (e: Exception) {
            return null
        }
    }

    private fun encryptData(data: ByteArray): Pair<ByteArray, ByteArray>? {
        val masterKey = getOrCreateMasterKey() ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(data)
        return Pair(iv, ciphertext)
    }

    private fun decryptData(iv: ByteArray, ciphertext: ByteArray): ByteArray? {
        val masterKey = getOrCreateMasterKey() ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, masterKey, spec)
        return cipher.doFinal(ciphertext)
    }

    private fun persistEncryptedString(key: String, value: String?) {
        if (value == null) {
            removeEncryptedEntry(key)
            return
        }
        persistEncryptedBytes(key, value.toByteArray(Charsets.UTF_8))
    }

    private fun persistEncryptedBytes(key: String, value: ByteArray?) {
        val prefs = getPrefs() ?: return
        if (value == null) {
            removeEncryptedEntry(key)
            return
        }
        val encrypted = encryptData(value)
        if (encrypted != null) {
            val ivBase64 = Base64.encodeToString(encrypted.first, Base64.NO_WRAP)
            val cipherBase64 = Base64.encodeToString(encrypted.second, Base64.NO_WRAP)
            prefs.edit()
                .putString("${key}_iv", ivBase64)
                .putString("${key}_data", cipherBase64)
                .apply()
        }
    }

    private fun loadEncryptedString(key: String): String? {
        val bytes = loadEncryptedBytes(key) ?: return null
        return String(bytes, Charsets.UTF_8)
    }

    private fun loadEncryptedBytes(key: String): ByteArray? {
        val prefs = getPrefs() ?: return null
        val ivBase64 = prefs.getString("${key}_iv", null) ?: return null
        val cipherBase64 = prefs.getString("${key}_data", null) ?: return null
        val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
        val ciphertext = Base64.decode(cipherBase64, Base64.NO_WRAP)
        return decryptData(iv, ciphertext)
    }

    private fun removeEncryptedEntry(key: String) {
        val prefs = getPrefs() ?: return
        prefs.edit()
            .remove("${key}_iv")
            .remove("${key}_data")
            .apply()
    }

    private fun loadEncryptedCredentials() {
        if (context == null) return
        cloudApiKey = loadEncryptedString("cloud_api_key")
        motoCaCertPem = loadEncryptedString("moto_ca_pem")
        motoTransportCertPem = loadEncryptedString("moto_cert_pem")
        motoTransportKeyPem = loadEncryptedString("moto_key_pem")
        motoAppPublicKey = loadEncryptedString("moto_app_pubkey")
        motoAppPrivateKey = loadEncryptedBytes("moto_app_privkey")
        motoPinnedPeerPublicKey = loadEncryptedString("moto_peer_pubkey")
        motoSessionKey = loadEncryptedBytes("moto_session_key")
        motoIsPaired = loadEncryptedString("moto_paired") == "true"

        val host = loadEncryptedString("endpoint_host") ?: EndpointConfig.DEFAULT_MOTO_HOST
        val port = loadEncryptedString("endpoint_port")?.toIntOrNull() ?: EndpointConfig.DEFAULT_MOTO_PORT
        val useTls = loadEncryptedString("endpoint_use_tls")?.toBooleanStrictOrNull() ?: true
        endpointConfig = EndpointConfig(host = host, port = port, useTls = useTls)

        val consumedRaw = loadEncryptedString("consumed_package_ids") ?: ""
        consumedPackageIds.clear()
        if (consumedRaw.isNotBlank()) {
            consumedPackageIds.addAll(consumedRaw.split(",").filter { it.isNotBlank() })
        }
    }
}
