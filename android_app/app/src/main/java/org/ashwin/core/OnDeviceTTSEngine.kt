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
 * 1. Strict discovery and enumeration of all locally installed TTS voices.
 * 2. Strict filtering for offline, on-device English voices only (voice.isNetworkConnectionRequired == false).
 * 3. Rejection of network synthesis voices and non-English voices (e.g. ur-PK, hi-IN).
 * 4. Priority selection for genuine English male voices (en_IN, en_US, en_GB).
 * 5. Honest fallback and reporting if only neutral/female local English voices are installed on-device.
 * 6. Natural speech delivery (pitch: 1.0f, speech rate: 0.98f) without artificial frequency manipulation.
 * 7. Speech normalization via SpeechNormalizer before synthesis.
 */
class OnDeviceTTSEngine(
    private val context: Context?,
    private val onInitComplete: ((Boolean) -> Unit)? = null
) : TextToSpeech.OnInitListener {

    companion object {
        private const val TAG = "ASHWIN_ON_DEVICE_TTS"
    }

    data class VoiceCandidate(
        val name: String,
        val locale: Locale,
        val isNetworkConnectionRequired: Boolean,
        val quality: Int,
        val latency: Int,
        val gender: String,
        val isUsableOffline: Boolean,
        val isEnglish: Boolean,
        val isMale: Boolean
    )

    private var tts: TextToSpeech? = null
    private var isInitialized = false
    private var selectedLocalVoice: Voice? = null
    private var enginePackageName: String? = null
    private val discoveredVoices = mutableListOf<VoiceCandidate>()

    init {
        if (context != null) {
            tts = TextToSpeech(context, this)
        }
    }

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS && tts != null) {
            val engine = tts!!
            enginePackageName = engine.defaultEngine ?: context?.packageName

            // Configure natural human pitch and rate
            engine.setPitch(1.0f)
            engine.setSpeechRate(0.98f)

            // 1. Enumerate and log ALL voices
            enumerateAllVoices(engine)

            // 2. Select best offline English voice according to priority
            val verifiedVoice = selectBestLocalEnglishVoice(engine)
            if (verifiedVoice != null) {
                engine.language = verifiedVoice.locale
                engine.voice = verifiedVoice
                selectedLocalVoice = verifiedVoice
                isInitialized = true

                val candidateInfo = discoveredVoices.firstOrNull { it.name == verifiedVoice.name }
                Log.i(
                    TAG,
                    "Selected Active Voice: ${verifiedVoice.name} | Locale: ${verifiedVoice.locale} | Gender: ${candidateInfo?.gender ?: "Unknown"} | Engine: $enginePackageName"
                )
                onInitComplete?.invoke(true)
            } else {
                Log.w(TAG, "No verified offline English voice found. Failing closed to text-only output.")
                isInitialized = false
                onInitComplete?.invoke(false)
            }
        } else {
            Log.e(TAG, "TextToSpeech initialization failed with status: $status")
            isInitialized = false
            onInitComplete?.invoke(false)
        }
    }

    private fun enumerateAllVoices(engine: TextToSpeech) {
        discoveredVoices.clear()
        val voices = engine.voices ?: return

        Log.i(TAG, "================ ENUMERATING ALL TTS VOICES (${voices.size} total) ================")
        for (voice in voices) {
            val isLocal = !voice.isNetworkConnectionRequired &&
                    !voice.features.contains(TextToSpeech.Engine.KEY_FEATURE_NETWORK_SYNTHESIS)
            val isLangAvailable = engine.isLanguageAvailable(voice.locale) >= TextToSpeech.LANG_AVAILABLE
            val isUsableOffline = isLocal && isLangAvailable
            val isEnglish = voice.locale.language.equals("en", ignoreCase = true) ||
                    voice.locale.isO3Language.equals("eng", ignoreCase = true)

            val isMale = evaluateIsMale(voice)
            val isFemale = evaluateIsFemale(voice)
            val gender = when {
                isMale -> "Male"
                isFemale -> "Female"
                else -> "Neutral/Unspecified"
            }

            val candidate = VoiceCandidate(
                name = voice.name,
                locale = voice.locale,
                isNetworkConnectionRequired = voice.isNetworkConnectionRequired,
                quality = voice.quality,
                latency = voice.latency,
                gender = gender,
                isUsableOffline = isUsableOffline,
                isEnglish = isEnglish,
                isMale = isMale
            )
            discoveredVoices.add(candidate)

            Log.i(
                TAG,
                "Voice: name='${voice.name}' | locale='${voice.locale}' | offline=$isUsableOffline | gender=$gender | quality=${voice.quality} | latency=${voice.latency}"
            )
        }
        Log.i(TAG, "================ END OF VOICE ENUMERATION ================")
    }

    private fun selectBestLocalEnglishVoice(engine: TextToSpeech): Voice? {
        val voices = engine.voices ?: return null

        val localEnglishVoices = voices.filter { voice ->
            val isLocal = !voice.isNetworkConnectionRequired &&
                    !voice.features.contains(TextToSpeech.Engine.KEY_FEATURE_NETWORK_SYNTHESIS)
            val isEnglish = voice.locale.language.equals("en", ignoreCase = true) ||
                    voice.locale.isO3Language.equals("eng", ignoreCase = true)
            val isLangAvailable = engine.isLanguageAvailable(voice.locale) >= TextToSpeech.LANG_AVAILABLE
            isLocal && isEnglish && isLangAvailable
        }

        if (localEnglishVoices.isEmpty()) {
            Log.w(TAG, "No local English voice available on device.")
            return null
        }

        // Priority 1: English India Male Voice
        val enInMale = localEnglishVoices.firstOrNull { voice ->
            voice.locale.country.equals("IN", ignoreCase = true) && evaluateIsMale(voice)
        }
        if (enInMale != null) {
            Log.i(TAG, "Selected Priority 1 (en_IN Male): ${enInMale.name}")
            return enInMale
        }

        // Priority 2: English US / UK Male Voice
        val enOtherMale = localEnglishVoices.firstOrNull { voice ->
            (voice.locale.country.equals("US", ignoreCase = true) || voice.locale.country.equals("GB", ignoreCase = true)) &&
                    evaluateIsMale(voice)
        }
        if (enOtherMale != null) {
            Log.i(TAG, "Selected Priority 2 (en_US/GB Male): ${enOtherMale.name}")
            return enOtherMale
        }

        // Priority 3: Any verified English Male Voice
        val anyEnglishMale = localEnglishVoices.firstOrNull { voice ->
            evaluateIsMale(voice)
        }
        if (anyEnglishMale != null) {
            Log.i(TAG, "Selected Priority 3 (Any English Male): ${anyEnglishMale.name}")
            return anyEnglishMale
        }

        // Priority 4: Highest quality English India voice (en_IN)
        val enInVoice = localEnglishVoices.firstOrNull { voice ->
            voice.locale.country.equals("IN", ignoreCase = true)
        }
        if (enInVoice != null) {
            Log.i(TAG, "Fallback: Selected highest quality local English India voice: ${enInVoice.name} (Note: device has no local male voice installed)")
            return enInVoice
        }

        // Priority 5: Any high quality local English voice
        val defaultEnglishVoice = localEnglishVoices.first()
        Log.i(TAG, "Fallback: Selected default local English voice: ${defaultEnglishVoice.name}")
        return defaultEnglishVoice
    }

    private fun evaluateIsMale(voice: Voice): Boolean {
        val nameLower = voice.name.lowercase(Locale.ROOT)
        val features = voice.features?.joinToString(" ")?.lowercase(Locale.ROOT) ?: ""
        return nameLower.contains("male") && !nameLower.contains("female") ||
                features.contains("male") && !features.contains("female") ||
                nameLower.contains("#m") || nameLower.contains("-male") ||
                nameLower.contains("en-us-x-sfg#male") || nameLower.contains("en-in-x-cfl#male") ||
                nameLower.contains("en-in-x-ahp#male") || nameLower.contains("en-gb-x-rjs#male") ||
                nameLower.contains("en-us-x-iom") || nameLower.contains("en-us-x-iob") ||
                nameLower.contains("en-in-x-ene-local") || nameLower.contains("en-in-x-cfl-local")
    }

    private fun evaluateIsFemale(voice: Voice): Boolean {
        val nameLower = voice.name.lowercase(Locale.ROOT)
        val features = voice.features?.joinToString(" ")?.lowercase(Locale.ROOT) ?: ""
        return nameLower.contains("female") || features.contains("female") ||
                nameLower.contains("#f") || nameLower.contains("-female") ||
                nameLower.contains("en-us-x-sfg#female") || nameLower.contains("en-in-x-enc-local") ||
                nameLower.contains("en-in-x-end-local") || nameLower.contains("en-in-x-cfl#female")
    }

    interface TTSPlaybackListener {
        fun onSpeechStart(utteranceId: String)
        fun onSpeechDone(utteranceId: String)
        fun onSpeechError(utteranceId: String, errorCode: Int)
    }

    private var playbackListener: TTSPlaybackListener? = null

    fun setPlaybackListener(listener: TTSPlaybackListener?) {
        this.playbackListener = listener
    }

    private fun setupUtteranceListener() {
        tts?.setOnUtteranceProgressListener(object : android.speech.tts.UtteranceProgressListener() {
            override fun onStart(utteranceId: String?) {
                utteranceId?.let { playbackListener?.onSpeechStart(it) }
            }

            override fun onDone(utteranceId: String?) {
                utteranceId?.let { playbackListener?.onSpeechDone(it) }
            }

            @Deprecated("Deprecated in Java")
            override fun onError(utteranceId: String?) {
                utteranceId?.let { playbackListener?.onSpeechError(it, -1) }
            }

            override fun onError(utteranceId: String?, errorCode: Int) {
                utteranceId?.let { playbackListener?.onSpeechError(it, errorCode) }
            }
        })
    }

    fun isLocalTtsAvailable(): Boolean = isInitialized && selectedLocalVoice != null

    fun getSelectedVoiceName(): String? = selectedLocalVoice?.name

    fun getSelectedVoiceLocale(): Locale? = selectedLocalVoice?.locale

    fun getDiscoveredVoices(): List<VoiceCandidate> = discoveredVoices.toList()

    fun speak(rawText: String, utteranceId: String = "ASHWIN_TTS_${System.currentTimeMillis()}"): Boolean {
        if (!isLocalTtsAvailable() || tts == null) {
            Log.w(TAG, "TTS not available on-device. Suppressing voice audio; text-only output.")
            return false
        }
        setupUtteranceListener()
        // Pass text through deterministic local speech normalizer
        val normalizedText = SpeechNormalizer.normalize(rawText)
        Log.i(TAG, "Normalized speech text: '$normalizedText'")
        tts?.speak(normalizedText, TextToSpeech.QUEUE_FLUSH, null, utteranceId)
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
