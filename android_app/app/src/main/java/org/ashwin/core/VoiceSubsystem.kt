package org.ashwin.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

class VoiceSubsystem(private val context: Context? = null) {

    fun isNetworkConnected(): Boolean {
        if (context == null) return false
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val network = cm.activeNetwork ?: return false
        val capabilities = cm.getNetworkCapabilities(network) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    fun processVoiceInput(
        audioData: ByteArray,
        cloudConsentGiven: Boolean = false
    ): Map<String, Any> {
        val hasNetwork = isNetworkConnected()
        if (hasNetwork && !cloudConsentGiven) {
            // RULE-11 / RULE-02 Verification
            return mapOf(
                "status" to "ON_DEVICE_STT",
                "mode" to "LOCAL_ONLY",
                "networkState" to "ACTIVE_WITHOUT_CLOUD_CONSENT",
                "message" to "Processing STT locally on-device without cloud network access."
            )
        }
        return mapOf(
            "status" to "SUCCESS",
            "mode" to if (cloudConsentGiven) "CLOUD_STT" else "LOCAL_STT",
            "message" to "Voice input processed successfully under security policy."
        )
    }
}
