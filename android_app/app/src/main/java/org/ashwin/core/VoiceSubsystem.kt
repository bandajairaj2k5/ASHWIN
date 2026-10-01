package org.ashwin.core

import android.content.Context
import android.util.Log

/**
 * ASHWIN Voice Subsystem (Phase 3 / Stage F, Section 2.7, Section 11, RULE-01, RULE-02, RULE-11).
 *
 * Coordinates:
 * Microphone -> OnDeviceSTTEngine -> InputClassifier -> CoreSession.memoryStore -> AIRouter -> OnDeviceTTSEngine
 * Strictly bound to CoreSession-owned security components and lifecycle.
 */
class VoiceSubsystem(
    val session: CoreSession,
    val sttEngine: OnDeviceSTTEngine = OnDeviceSTTEngine(null),
    val ttsEngine: OnDeviceTTSEngine = OnDeviceTTSEngine(null)
) {
    companion object {
        private const val TAG = "ASHWIN_VOICE_SUBSYSTEM"
    }

    interface VoiceTurnCallback {
        fun onTranscription(text: String, dataClass: String)
        fun onModelResponse(response: String, isLocal: Boolean, providerUsed: String)
        fun onAudioPlaybackStarted()
        fun onError(error: String)
    }

    val memoryStore: EphemeralMemoryStore
        get() = session.memoryStore

    val classifier: InputClassifier
        get() = session.classifier

    val router: AIRouter
        get() = session.router

    fun isVoiceInputAvailable(): Boolean = sttEngine.isOnDeviceAvailable()

    fun isTtsAvailable(): Boolean = ttsEngine.isLocalTtsAvailable()

    fun startVoiceTurn(userCloudConsent: Boolean = false, callback: VoiceTurnCallback) {
        if (!session.isActive) {
            callback.onError("CoreSession is inactive. Voice processing rejected.")
            return
        }

        if (!sttEngine.isOnDeviceAvailable()) {
            callback.onError("On-device speech recognition is unavailable. Voice input is disabled. Please use typed input.")
            return
        }

        sttEngine.startListening(object : OnDeviceSTTEngine.STTCallback {
            override fun onTranscriptionResult(text: String) {
                if (text.isBlank()) {
                    callback.onError("No speech recognized. Please try again.")
                    return
                }

                // Process through InputClassifier (Assigns PROTECTED by default, runs SecretScanner)
                val classifiedContext = classifier.processUserInput(
                    rawText = text,
                    source = SourceDomain.PHONE,
                    isStt = true
                )

                callback.onTranscription(classifiedContext.content, classifiedContext.dataClass.name)

                // Store in CoreSession's ephemeral RAM memory
                session.memoryStore.addContext(classifiedContext)

                // Route through AIRouter (Sole model delivery boundary)
                val routerResult = router.processContext(
                    context = classifiedContext,
                    userCloudConsent = userCloudConsent
                )

                if (routerResult["status"] != "SUCCESS") {
                    val msg = routerResult["message"] as? String ?: "Routing denied by security policy."
                    callback.onError(msg)
                    return
                }

                val responseText = routerResult["response"] as? String ?: ""
                val isLocal = routerResult["is_local"] as? Boolean ?: true
                val providerUsed = routerResult["provider_used"] as? String ?: "LocalAI"

                callback.onModelResponse(responseText, isLocal, providerUsed)

                // Synthesize on-device speech
                val spoken = ttsEngine.speak(responseText)
                if (spoken) {
                    callback.onAudioPlaybackStarted()
                }
            }

            override fun onError(errorCode: Int, message: String) {
                Log.e(TAG, "Voice turn error [$errorCode]: $message")
                callback.onError(message)
            }
        })
    }

    fun reset() {
        ttsEngine.stop()
        session.memoryStore.clear()
    }

    fun shutdown() {
        ttsEngine.shutdown()
        session.memoryStore.clear()
    }
}
