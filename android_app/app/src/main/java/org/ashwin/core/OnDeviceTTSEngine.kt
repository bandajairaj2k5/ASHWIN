package org.ashwin.core

import android.content.Context
import android.speech.tts.TextToSpeech
import android.speech.tts.Voice
import android.util.Log
import java.util.Locale

/**
 * On-Device Text-To-Speech Engine (Phase 3 / Stage F, Section 2.7).
 *
 * Enforces:
 * 1. Strict filtering for offline, on-device voices only (voice.isNetworkConnectionRequired == false).
 * 2. Rejection of network synthesis voices.
 * 3. Configuration of customized voice delivery: deep, calm, authoritative (pitch: 0.85f, rate: 0.95f).
 * 4. Fails closed to text-only delivery if no local voice is available.
 */
class OnDeviceTTSEngine(
    private val context: Context?,
    private val onInitComplete: ((Boolean) -> Unit)? = null
) : TextToSpeech.OnInitListener {

    companion object {
        private const val TAG = "ASHWIN_ON_DEVICE_TTS"
    }

    private var tts: TextToSpeech? = null
    private var isInitialized = false
    private var selectedLocalVoice: Voice? = null

    init {
        if (context != null) {
            tts = TextToSpeech(context, this)
        }
    }

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS && tts != null) {
            val engine = tts!!
            engine.language = Locale.US
            engine.setPitch(0.85f)
            engine.setSpeechRate(0.95f)

            // Select only verified local on-device voice
            val verifiedVoice = findLocalOfflineVoice(engine)
            if (verifiedVoice != null) {
                engine.voice = verifiedVoice
                selectedLocalVoice = verifiedVoice
                isInitialized = true
                Log.i(TAG, "Selected verified local on-device voice: ${verifiedVoice.name}")
                onInitComplete?.invoke(true)
            } else {
                Log.w(TAG, "No verified offline voice found. Failing closed to text-only output.")
                isInitialized = false
                onInitComplete?.invoke(false)
            }
        } else {
            Log.e(TAG, "TextToSpeech initialization failed with status: $status")
            isInitialized = false
            onInitComplete?.invoke(false)
        }
    }

    private fun findLocalOfflineVoice(engine: TextToSpeech): Voice? {
        val voices = engine.voices ?: return null
        for (voice in voices) {
            val isLocal = !voice.isNetworkConnectionRequired &&
                    !voice.features.contains(TextToSpeech.Engine.KEY_FEATURE_NETWORK_SYNTHESIS)
            val isLangAvailable = engine.isLanguageAvailable(voice.locale) >= TextToSpeech.LANG_AVAILABLE
            if (isLocal && isLangAvailable) {
                return voice
            }
        }
        return null
    }

    fun isLocalTtsAvailable(): Boolean = isInitialized && selectedLocalVoice != null

    fun getSelectedVoiceName(): String? = selectedLocalVoice?.name

    fun speak(text: String): Boolean {
        if (!isLocalTtsAvailable() || tts == null) {
            Log.w(TAG, "TTS not available on-device. Suppressing voice audio; text-only output.")
            return false
        }
        tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, "ASHWIN_TTS_${System.currentTimeMillis()}")
        return true
    }

    fun stop() {
        tts?.stop()
    }

    fun shutdown() {
        tts?.stop()
        tts?.shutdown()
        tts = null
        isInitialized = false
    }
}
