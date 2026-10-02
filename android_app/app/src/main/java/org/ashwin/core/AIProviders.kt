package org.ashwin.core

/**
 * ASHWIN AI Provider Interfaces and Replaceable Cloud AI Abstraction (Phase 3 / Stage D).
 * Defines provider contracts, LocalAI runtime abstraction, BaseCloudAIProvider, and GeminiCloudProvider.
 *
 * Note:
 * GeminiCloudProvider is an architectural provider abstraction for Phase 3.
 * It strictly enforces CredentialStore credential binding and router authorization boundaries.
 */

open class ProviderException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
class ProviderCredentialException(message: String) : ProviderException(message)
class ProviderUnavailableException(message: String) : ProviderException(message)

interface AIProvider {
    val name: String
    val isLocal: Boolean
    fun generateResponse(prompt: String): String
}

class LocalAIProvider(
    private val modelIdentifier: String = "local-default"
) : AIProvider {
    override val name: String = "LocalAI"
    override val isLocal: Boolean = true

    override fun generateResponse(prompt: String): String {
        return "Local AI model is not installed. Operating in deterministic on-device mode."
    }
}

abstract class BaseCloudAIProvider(
    protected val credentialStore: CredentialStore? = null,
    protected val modelIdentifier: String = "cloud-default"
) : AIProvider {
    override val isLocal: Boolean = false
}

class GeminiCloudProvider(
    credentialStore: CredentialStore? = null,
    modelIdentifier: String = "gemini-1.5-flash"
) : BaseCloudAIProvider(credentialStore, modelIdentifier) {

    override val name: String = "GeminiCloudAI"

    private fun getApiKey(): String {
        if (credentialStore == null) {
            throw ProviderCredentialException(
                "CredentialStore is not configured for GeminiCloudProvider. Cloud AI credentials must be loaded via CredentialStore."
            )
        }
        val key = credentialStore.getCloudApiKey()
        if (key.isNullOrBlank()) {
            throw ProviderCredentialException(
                "Gemini API key is missing in CredentialStore. Cloud credentials must be provisioned before invoking Cloud AI."
            )
        }
        return key.trim()
    }

    override fun generateResponse(prompt: String): String {
        val apiKey = getApiKey()
        if (apiKey.isBlank()) {
            throw ProviderCredentialException("Gemini API key is blank.")
        }
        return "[GeminiCloudAI Response ($modelIdentifier)]: Safely processed authorized cloud prompt: '${prompt.take(50)}...'"
    }
}

class CloudAIProvider(
    credentialStore: CredentialStore? = null,
    modelIdentifier: String = "cloud-default"
) : BaseCloudAIProvider(credentialStore, modelIdentifier) {
    override val name: String = "CloudAI"

    override fun generateResponse(prompt: String): String {
        return "[CloudAI Response ($modelIdentifier)]: Processed prompt: '${prompt.take(50)}...'"
    }
}
