package org.ashwin.core

/**
 * ASHWIN Endpoint Configuration (Phase 1, Section 7, Section 10).
 * Manages network endpoint parameters for remote servers (such as Moto G3).
 * Decouples physical host/IP from hardcoded application logic while maintaining
 * strict certificate pinning and mTLS validation.
 */
data class EndpointConfig(
    val host: String = DEFAULT_MOTO_HOST,
    val port: Int = DEFAULT_MOTO_PORT,
    val useTls: Boolean = true,
    val pinnedCaCertPem: String? = null
) {
    companion object {
        const val DEFAULT_MOTO_HOST = "10.202.197.15"
        const val DEFAULT_MOTO_PORT = 8443
        const val DEFAULT_MOTO_SERVER_CN = "MOTO-G3-STORAGE-ENDPOINT"
    }

    init {
        require(host.isNotBlank()) { "Endpoint host cannot be blank" }
        require(port in 1..65535) { "Endpoint port must be between 1 and 65535 (got: $port)" }
    }

    /**
     * Constructs the full base URL.
     * Enforces HTTPS/TLS unless explicitly configured otherwise for tests.
     */
    val baseUrl: String
        get() {
            val scheme = if (useTls) "https" else "http"
            return "$scheme://$host:$port"
        }

    fun isConfigured(): Boolean {
        return host.isNotBlank() && port in 1..65535
    }
}
