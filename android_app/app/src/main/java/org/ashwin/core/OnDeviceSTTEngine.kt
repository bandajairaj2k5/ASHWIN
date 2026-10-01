package org.ashwin.core

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.util.Log

/**
 * On-Device Speech-to-Text Engine (Phase 3 / Stage F, RULE-11, RULE-02).
 *
 * Enforces:
 * 1. Verifies SpeechRecognizer.isOnDeviceRecognitionAvailable(context) == true.
 * 2. Uses strictly SpeechRecognizer.createOnDeviceSpeechRecognizer(context).
 *    (Prohibits generic createSpeechRecognizer).
 * 3. Configures RecognizerIntent with EXTRA_PREFER_OFFLINE.
 * 4. Fails closed if on-device recognition is unavailable or unverified.
 */
class OnDeviceSTTEngine(private val context: Context?) {

    companion object {
        private const val TAG = "ASHWIN_ON_DEVICE_STT"
    }

    interface STTCallback {
        fun onTranscriptionResult(text: String)
        fun onError(errorCode: Int, message: String)
    }

    fun isOnDeviceAvailable(): Boolean {
        if (context == null) return false
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            SpeechRecognizer.isOnDeviceRecognitionAvailable(context)
        } else {
            false
        }
    }

    fun startListening(callback: STTCallback): Boolean {
        if (context == null) {
            callback.onError(-1, "Context is null. On-device STT cannot be initialized.")
            return false
        }

        if (!isOnDeviceAvailable()) {
            Log.w(TAG, "RULE-11: On-device speech recognition is not available. Failing closed.")
            callback.onError(-2, "On-device speech recognition is unavailable. Voice input is disabled. Please use typed input.")
            return false
        }

        return try {
            val recognizer = SpeechRecognizer.createOnDeviceSpeechRecognizer(context)
            val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
                putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
                putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, false)
                putExtra(RecognizerIntent.EXTRA_PREFER_OFFLINE, true)
            }

            recognizer.setRecognitionListener(object : RecognitionListener {
                override fun onReadyForSpeech(params: Bundle?) {}
                override fun onBeginningOfSpeech() {}
                override fun onRmsChanged(rmsdB: Float) {}
                override fun onBufferReceived(buffer: ByteArray?) {}
                override fun onEndOfSpeech() {}
                override fun onError(error: Int) {
                    Log.e(TAG, "On-device recognition error: $error")
                    callback.onError(error, "Speech recognition failed with code $error. Please use typed input.")
                    recognizer.destroy()
                }

                override fun onResults(results: Bundle?) {
                    val matches = results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
                    val text = matches?.firstOrNull() ?: ""
                    callback.onTranscriptionResult(text)
                    recognizer.destroy()
                }

                override fun onPartialResults(partialResults: Bundle?) {}
                override fun onEvent(eventType: Int, params: Bundle?) {}
            })

            recognizer.startListening(intent)
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start on-device speech recognizer: ${e.message}", e)
            callback.onError(-3, "Failed to start on-device speech recognition. Please use typed input.")
            false
        }
    }
}
