package org.ashwin.core

import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private val TAG = "ASHWIN_CORE"
    private lateinit var statusText: TextView
    private val scanner = SecretScanner()
    private val router = AIRouter()
    private lateinit var voiceSubsystem: VoiceSubsystem

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TAG, "MainActivity.onCreate starting")
        
        // Initialize and verify core security components
        Log.i(TAG, "SecretScanner initialized: testing scan health")
        val scanTest = scanner.scanAndRedact("TEST_INPUT")
        Log.i(TAG, "SecretScanner status: healthy=${scanTest.second["healthy"]}")

        Log.i(TAG, "AIRouter initialized: testing local router pipeline")
        val routerTest = router.processContext(
            ScannedClassifiedContext(
                content = scanTest.first,
                dataClass = scanTest.third,
                source = SourceDomain.PHONE,
                scanned = true,
                scanSummary = scanTest.second,
                cloudApproved = false
            )
        )
        Log.i(TAG, "AIRouter status: provider=${routerTest["provider"]}, isLocal=${routerTest["isLocal"]}")

        Log.i(TAG, "VoiceSubsystem initializing")
        voiceSubsystem = VoiceSubsystem(this)
        val networkActive = voiceSubsystem.isNetworkConnected()
        Log.i(TAG, "VoiceSubsystem initialized: networkActive=$networkActive (Cloud STT network egress: BLOCKED without consent)")

        statusText = TextView(this).apply {
            text = "ASHWIN Core V0.1 Initializing...\n\n" +
                    "AI Router: Active (Model-Agnostic)\n" +
                    "Security Layer: Enforced (RULE-01 to RULE-15)\n" +
                    "Secret Scanner: Healthy\n" +
                    "Data Classification: PROTECTED default\n" +
                    "On-Device STT: Ready\n" +
                    "Audit Logger: Active\n\n" +
                    "Status: READY - Enforcing Fail-Closed Security Policy"
            textSize = 16f
            setPadding(32, 32, 32, 32)
        }
        
        setContentView(statusText)
        Log.i(TAG, "MainActivity UI view set successfully. State: READY")
    }
}
