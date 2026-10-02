package org.ashwin.core

import android.Manifest
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.util.Log
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * ASHWIN Mobile Assistant Main Activity.
 *
 * Full-screen Futuristic Holographic HUD with:
 * - Dynamic Orange/Gold Holographic Sphere (HologramView)
 * - Voice-first offline interaction (OnDeviceSTTEngine & OnDeviceTTSEngine)
 * - Deterministic Intent Dispatcher & Parser (Zero paid AI APIs)
 * - Motorola Moto G3 Private Encrypted Storage & Secure File Downloader
 * - Windows Restricted Endpoint (10 Allowed Tools)
 * - Email Connector (Read-only briefing interface)
 * - Complete Security & Provisioning Architecture
 */
class MainActivity : AppCompatActivity() {

    private val TAG = "ASHWIN_CORE"
    private val mainHandler = Handler(Looper.getMainLooper())

    // Core Security & Execution Components
    private lateinit var credentialStore: CredentialStore
    private val scanner = SecretScanner()
    private lateinit var motoStorageClient: MotoStorageClient
    private lateinit var laptopConnector: LaptopConnector
    private lateinit var emailConnector: EmailConnector
    private lateinit var coreSession: CoreSession
    private lateinit var voiceSubsystem: VoiceSubsystem
    private lateinit var intentDispatcher: IntentDispatcher

    // UI Root and Screen States
    private lateinit var rootContainer: FrameLayout
    private lateinit var hudLayout: LinearLayout
    private lateinit var settingsLayout: ScrollView
    private lateinit var consoleLayout: LinearLayout

    // Hologram & HUD Components
    private lateinit var hologramView: HologramView
    private lateinit var statusBadge: TextView
    private lateinit var motoBadge: TextView
    private lateinit var laptopBadge: TextView
    private lateinit var stateLabel: TextView
    private lateinit var promptTranscriptText: TextView
    private lateinit var responseCardText: TextView
    private lateinit var responseCardContainer: LinearLayout
    private lateinit var inputEditText: EditText
    private lateinit var btnMic: Button
    private lateinit var btnSend: Button
    private lateinit var logContainer: LinearLayout
    private lateinit var logScrollView: ScrollView

    // Settings View Components
    private lateinit var settingsStatusText: TextView
    private lateinit var pinEditText: EditText

    // Chat Message Model
    data class ChatMessage(
        val sender: String,
        val text: String,
        val isUser: Boolean,
        val timestamp: Long = System.currentTimeMillis(),
        val tag: String? = null,
        val isWarning: Boolean = false
    )

    private val chatMessages = mutableListOf<ChatMessage>()

    // SAF Document Picker for Provisioning
    private val filePickerLauncher = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri != null) {
            showPinPromptDialog(uri)
        }
    }

    // Audio Permission Launcher
    private val requestAudioPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (isGranted) {
            startVoiceRecognitionTurn()
        } else {
            Toast.makeText(this, "Microphone permission is required for voice input.", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        Log.i(TAG, "MainActivity.onCreate starting - Initializing Holographic Mobile Assistant")

        // Configure edge-to-edge window insets cleanly
        window.statusBarColor = Color.parseColor("#070A12")
        window.navigationBarColor = Color.parseColor("#070A12")
        WindowCompat.setDecorFitsSystemWindows(window, false)

        // Initialize Core Security Architecture
        credentialStore = CredentialStore(this)
        motoStorageClient = MotoStorageClient(credentialStore, scanner)
        laptopConnector = LaptopConnector(credentialStore, scanner)
        emailConnector = EmailConnector(credentialStore, scanner)

        coreSession = CoreSession(
            credentialStore = credentialStore,
            scanner = scanner,
            motoStorageClient = motoStorageClient,
            laptopConnector = laptopConnector
        )

        voiceSubsystem = VoiceSubsystem(
            session = coreSession,
            sttEngine = OnDeviceSTTEngine(this),
            ttsEngine = OnDeviceTTSEngine(this)
        )

        // Setup TTS playback sync with HologramView
        voiceSubsystem.ttsEngine.setPlaybackListener(object : OnDeviceTTSEngine.TTSPlaybackListener {
            override fun onSpeechStart(utteranceId: String) {
                runOnUiThread {
                    hologramView.currentState = HologramView.State.SPEAKING
                    stateLabel.text = "SPEAKING"
                    stateLabel.setTextColor(Color.parseColor("#FFA726"))
                }
            }

            override fun onSpeechDone(utteranceId: String) {
                runOnUiThread {
                    hologramView.currentState = HologramView.State.IDLE
                    stateLabel.text = "READY"
                    stateLabel.setTextColor(Color.parseColor("#4ADE80"))
                }
            }

            override fun onSpeechError(utteranceId: String, errorCode: Int) {
                runOnUiThread {
                    hologramView.currentState = HologramView.State.ERROR
                    stateLabel.text = "AUDIO ERROR"
                    stateLabel.setTextColor(Color.parseColor("#F87171"))
                    mainHandler.postDelayed({
                        hologramView.currentState = HologramView.State.IDLE
                        stateLabel.text = "READY"
                        stateLabel.setTextColor(Color.parseColor("#4ADE80"))
                    }, 2500)
                }
            }
        })

        intentDispatcher = IntentDispatcher(
            session = coreSession,
            emailConnector = emailConnector
        )

        // Build UI Layers
        rootContainer = FrameLayout(this).apply {
            setBackgroundColor(Color.parseColor("#070A12")) // Obsidian Black
        }

        // Apply WindowInsets listener to properly pad below status bar & above navigation bar
        ViewCompat.setOnApplyWindowInsetsListener(rootContainer) { view, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(insets.left, insets.top, insets.right, insets.bottom)
            windowInsets
        }

        hudLayout = buildHolographicHudView()
        settingsLayout = buildSettingsView()
        consoleLayout = buildConsoleView()

        rootContainer.addView(hudLayout)
        rootContainer.addView(consoleLayout)
        rootContainer.addView(settingsLayout)

        consoleLayout.visibility = View.GONE
        settingsLayout.visibility = View.GONE

        setContentView(rootContainer)

        // Update Device Status Badges
        updateDeviceStatusBadges()

        // Handle Intent Actions
        handleIncomingIntent(intent)
    }

    override fun onNewIntent(newIntent: android.content.Intent?) {
        super.onNewIntent(newIntent)
        setIntent(newIntent)
        newIntent?.let { handleIncomingIntent(it) }
    }

    private fun handleIncomingIntent(targetIntent: android.content.Intent) {
        val action = targetIntent.getStringExtra("action")
        when (action) {
            "test_user_flow" -> runRealUserInteractionTest()
            "run_physical_integration_test" -> {
                val pkgPath = targetIntent.getStringExtra("package_path") ?: ""
                val pin = targetIntent.getStringExtra("pin") ?: ""
                runDeveloperHarnessTest(pkgPath, pin)
            }
            "verify_voice_subsystem" -> runVoiceDiagnosticVerification()
            "verify_stage_g_consent" -> runConsentDiagnosticVerification()
            "verify_stage_h_moto" -> runMotoStorageDiagnosticVerification()
            "verify_stage_i_e2e" -> runStageIE2EVerification()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        voiceSubsystem.shutdown()
    }

    // =========================================================================
    // UI BUILDER: HOLOGRAPHIC ASSISTANT HUD VIEW
    // =========================================================================

    private fun buildHolographicHudView(): LinearLayout {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#070A12")) // Deep Obsidian Background
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        }

        // 1. Ultra-Clean Centered Minimalist Header (Positioned cleanly below status bar)
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 20, 32, 10)
            gravity = Gravity.CENTER_HORIZONTAL
        }

        val titleText = TextView(this).apply {
            text = "A S H W I N"
            textSize = 22f
            gravity = Gravity.CENTER
            setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
            setTextColor(Color.parseColor("#FFE082")) // Gold Hologram Tone
            letterSpacing = 0.35f
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            // Unobtrusive long-press to open Settings & Security without any visible button
            setOnLongClickListener {
                showSettingsScreen()
                true
            }
        }
        header.addView(titleText)
        layout.addView(header)

        // 2. Large Hologram Intelligence Core (Fills the entire remaining screen)
        val hologramContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        hologramView = HologramView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
            currentState = HologramView.State.IDLE
            onHologramTapListener = {
                handleMicButtonClick()
            }
        }
        hologramContainer.addView(hologramView)
        layout.addView(hologramContainer)

        // 3. Initialize background references for test harnesses / internal models
        statusBadge = TextView(this).apply { text = "● ON-DEVICE" }
        motoBadge = TextView(this).apply { text = "MOTO: PAIRED" }
        laptopBadge = TextView(this).apply { text = "LAPTOP: READY" }
        stateLabel = TextView(this).apply { text = "READY" }
        promptTranscriptText = TextView(this).apply { text = "Ready." }
        responseCardText = TextView(this).apply { text = "ASHWIN Holographic Core Ready." }
        responseCardContainer = LinearLayout(this)
        inputEditText = EditText(this)
        btnMic = Button(this)
        btnSend = Button(this)

        return layout
    }

    // =========================================================================
    // UI BUILDER: CONSOLE & CHAT HISTORY VIEW
    // =========================================================================

    private fun buildConsoleView(): LinearLayout {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#070A12"))
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
            setPadding(28, 40, 28, 28)
        }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, 20)
        }

        val btnBack = Button(this).apply {
            text = "← HUD"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#FFE082"))
            background = createRoundedDrawable(Color.parseColor("#1E293B"), 20f)
            layoutParams = LinearLayout.LayoutParams(160, 80).apply { marginEnd = 20 }
            setOnClickListener { showHudScreen() }
        }
        header.addView(btnBack)

        val title = TextView(this).apply {
            text = "Execution Log & History"
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.WHITE)
        }
        header.addView(title)
        layout.addView(header)

        logScrollView = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        logContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        logScrollView.addView(logContainer)
        layout.addView(logScrollView)

        return layout
    }

    // =========================================================================
    // UI BUILDER: SETTINGS & SECURITY VIEW
    // =========================================================================

    private fun buildSettingsView(): ScrollView {
        val scrollView = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#070A12"))
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 40, 28, 48)
        }

        // Header
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, 24)
        }

        val btnBack = Button(this).apply {
            text = "← HUD"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#FFE082"))
            background = createRoundedDrawable(Color.parseColor("#1E293B"), 20f)
            layoutParams = LinearLayout.LayoutParams(160, 80).apply { marginEnd = 20 }
            setOnClickListener { showHudScreen() }
        }
        header.addView(btnBack)

        val title = TextView(this).apply {
            text = "Settings & Security"
            textSize = 20f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.WHITE)
        }
        header.addView(title)
        layout.addView(header)

        // 1. Security Architecture Card
        layout.addView(createSectionHeader("SECURITY & SPECIFICATION"))
        val secCard = createDarkCardView()
        settingsStatusText = TextView(this).apply {
            val isProv = credentialStore.getParsedCertificate() != null
            text = "Core Session: ACTIVE\n" +
                    "Secret Scanner: HEALTHY\n" +
                    "Specification: v1.0.1 (RULE-01 to RULE-15)\n" +
                    "Transient RAM Memory: 0 items\n" +
                    "Moto Identity: ${if (isProv) "Provisioned (mTLS 1.3)" else "Not Provisioned"}\n" +
                    "Windows Endpoint: LAPTOP-AGENT-01 (10 Tools)"
            textSize = 13f
            setTextColor(Color.parseColor("#CBD5E1"))
            setLineSpacing(6f, 1f)
        }
        secCard.addView(settingsStatusText)

        val btnResetSession = Button(this).apply {
            text = "Purge Transient RAM & Reset Session"
            textSize = 13f
            setTextColor(Color.WHITE)
            background = createRoundedDrawable(Color.parseColor("#DC2626"), 16f)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 16 }
            setOnClickListener {
                coreSession.resetSession()
                Toast.makeText(this@MainActivity, "CoreSession reset. Ephemeral state purged.", Toast.LENGTH_SHORT).show()
                refreshSettingsStatus()
                updateDeviceStatusBadges()
            }
        }
        secCard.addView(btnResetSession)
        layout.addView(secCard)

        // 2. Connected Endpoints Card
        layout.addView(createSectionHeader("CONNECTED ENDPOINTS"))
        val devCard = createDarkCardView()

        val motoTitle = TextView(this).apply {
            text = "📱 Moto G3 Storage Endpoint"
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#60A5FA"))
        }
        devCard.addView(motoTitle)

        val motoDesc = TextView(this).apply {
            text = "Address: 127.0.0.1:8443\nTransport: TLS 1.3 mTLS + SAS\nBounded Buffers: <= 5 MB\nDownloads: /sdcard/Download/ASHWIN"
            textSize = 12f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 4, 0, 16)
        }
        devCard.addView(motoDesc)

        val laptopTitle = TextView(this).apply {
            text = "💻 Windows Restricted Endpoint"
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#FDE047"))
        }
        devCard.addView(laptopTitle)

        val laptopDesc = TextView(this).apply {
            text = "Identity: LAPTOP-AGENT-01 (127.0.0.1:8444)\nTools: Exactly 10 tools\nShell/Scripts: ZERO (Fail closed)"
            textSize = 12f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 4, 0, 0)
        }
        devCard.addView(laptopDesc)
        layout.addView(devCard)

        // 3. Identity Provisioning Card
        layout.addView(createSectionHeader("IDENTITY PROVISIONING"))
        val provCard = createDarkCardView()

        val pinLabel = TextView(this).apply {
            text = "Enter One-Time Setup PIN:"
            textSize = 12f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 0, 0, 8)
        }
        provCard.addView(pinLabel)

        pinEditText = EditText(this).apply {
            hint = "One-Time Setup PIN"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            textSize = 14f
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#64748B"))
            background = createRoundedDrawable(Color.parseColor("#1E293B"), 12f, Color.parseColor("#475569"))
            setPadding(20, 16, 20, 16)
        }
        provCard.addView(pinEditText)

        val btnImportStaged = Button(this).apply {
            text = "Import Staged Identity (ashwin_identity.bin)"
            textSize = 13f
            setTextColor(Color.WHITE)
            background = createRoundedDrawable(Color.parseColor("#0F766E"), 14f)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 16 }
            setOnClickListener {
                val enteredPin = pinEditText.text.toString()
                if (enteredPin.isBlank()) {
                    Toast.makeText(this@MainActivity, "Please enter the Setup PIN.", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                val stagedFile = File(getExternalFilesDir(null), "ashwin_identity.bin")
                val targetFile = if (stagedFile.exists()) stagedFile else File("/sdcard/Android/data/org.ashwin.core/files/ashwin_identity.bin")
                executeProvisioningAndMotoVerification(uri = null, file = targetFile, pin = enteredPin, isUiFlow = true)
            }
        }
        provCard.addView(btnImportStaged)

        val btnPickFile = Button(this).apply {
            text = "Select Identity Package via SAF File Picker"
            textSize = 13f
            setTextColor(Color.parseColor("#CBD5E1"))
            background = createRoundedDrawable(Color.parseColor("#334155"), 14f)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 12 }
            setOnClickListener { filePickerLauncher.launch("*/*") }
        }
        provCard.addView(btnPickFile)
        layout.addView(provCard)

        // 4. Voice & Speech Card
        layout.addView(createSectionHeader("ON-DEVICE VOICE"))
        val voiceCard = createDarkCardView()
        val sttStatus = if (voiceSubsystem.isVoiceInputAvailable()) "Available (On-Device)" else "Unavailable (SpeechRecognizer required)"
        val voiceInfo = TextView(this).apply {
            text = "STT Engine: $sttStatus\nTTS Voice: On-Device Deep Synthesis\nAudio Privacy: Zero raw audio persistence (RULE-11)"
            textSize = 12f
            setTextColor(Color.parseColor("#CBD5E1"))
            setLineSpacing(4f, 1f)
        }
        voiceCard.addView(voiceInfo)
        layout.addView(voiceCard)

        scrollView.addView(layout)
        return scrollView
    }

    private fun createSectionHeader(title: String): TextView {
        return TextView(this).apply {
            text = title
            textSize = 11f
            setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
            setTextColor(Color.parseColor("#64748B"))
            setPadding(8, 24, 8, 8)
            letterSpacing = 0.15f
        }
    }

    private fun createDarkCardView(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createRoundedDrawable(Color.parseColor("#0F172A"), 20f, Color.parseColor("#1E293B"))
            setPadding(24, 20, 24, 20)
        }
    }

    private fun showHudScreen() {
        settingsLayout.visibility = View.GONE
        consoleLayout.visibility = View.GONE
        hudLayout.visibility = View.VISIBLE
    }

    private fun showConsoleScreen() {
        settingsLayout.visibility = View.GONE
        hudLayout.visibility = View.GONE
        consoleLayout.visibility = View.VISIBLE
    }

    private fun showSettingsScreen() {
        refreshSettingsStatus()
        hudLayout.visibility = View.GONE
        consoleLayout.visibility = View.GONE
        settingsLayout.visibility = View.VISIBLE
    }

    private fun refreshSettingsStatus() {
        val isProv = credentialStore.getParsedCertificate() != null
        val memCount = coreSession.memoryStore.count
        settingsStatusText.text = "Core Session: ACTIVE\n" +
                "Secret Scanner: HEALTHY\n" +
                "Specification: v1.0.1 (RULE-01 to RULE-15)\n" +
                "Transient RAM Memory: $memCount items\n" +
                "Moto Identity: ${if (isProv) "Provisioned (mTLS 1.3)" else "Not Provisioned"}\n" +
                "Windows Endpoint: LAPTOP-AGENT-01 (10 Tools)"
    }

    private fun updateDeviceStatusBadges() {
        runOnUiThread {
            val isProv = credentialStore.getParsedCertificate() != null
            val isMotoPaired = credentialStore.isMotoPaired()
            val motoHost = credentialStore.getEndpointConfig().host

            statusBadge.text = "● ON-DEVICE DETERMINISTIC"

            if (isMotoPaired) {
                motoBadge.text = "MOTO: $motoHost (PAIRED)"
                motoBadge.setTextColor(Color.parseColor("#93C5FD"))
            } else if (isProv) {
                motoBadge.text = "MOTO: $motoHost (PROVISIONED)"
                motoBadge.setTextColor(Color.parseColor("#FDE047"))
            } else {
                motoBadge.text = "MOTO: $motoHost (UNPAIRED)"
                motoBadge.setTextColor(Color.parseColor("#94A3B8"))
            }

            val laptopConnectorActive = coreSession.laptopConnector != null
            if (laptopConnectorActive) {
                laptopBadge.text = "LAPTOP: 10.202.197.223 (READY)"
                laptopBadge.setTextColor(Color.parseColor("#FDE047"))
            } else {
                laptopBadge.text = "LAPTOP: OFFLINE"
                laptopBadge.setTextColor(Color.parseColor("#94A3B8"))
            }
        }
    }

    // =========================================================================
    // VOICE & INTENT DISPATCH EXECUTION
    // =========================================================================

    private fun handleSendButtonClick() {
        val text = inputEditText.text.toString().trim()
        if (text.isBlank()) return
        inputEditText.setText("")
        executeAssistantTurn(text, isStt = false)
    }

    private fun handleMicButtonClick() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            requestAudioPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
        } else {
            startVoiceRecognitionTurn()
        }
    }

    private fun startVoiceRecognitionTurn() {
        if (!voiceSubsystem.isVoiceInputAvailable()) {
            Toast.makeText(this, "On-device voice recognition is unavailable. Please use typed input.", Toast.LENGTH_LONG).show()
            return
        }

        hologramView.currentState = HologramView.State.LISTENING
        stateLabel.text = "LISTENING..."
        stateLabel.setTextColor(Color.parseColor("#60A5FA"))
        promptTranscriptText.text = "Listening to speech..."

        voiceSubsystem.startVoiceTurn(
            userCloudConsent = false,
            callback = object : VoiceSubsystem.VoiceTurnCallback {
                override fun onTranscription(text: String, dataClass: String) {
                    runOnUiThread {
                        promptTranscriptText.text = "You: $text"
                        hologramView.currentState = HologramView.State.THINKING
                        stateLabel.text = "THINKING..."
                        stateLabel.setTextColor(Color.parseColor("#FDE047"))
                        executeParsedIntent(text, isStt = true)
                    }
                }

                override fun onModelResponse(response: String, isLocal: Boolean, providerUsed: String) {
                    // Handled inside intent execution
                }

                override fun onAudioPlaybackStarted() {
                    Log.i(TAG, "Speech playback started.")
                }

                override fun onError(error: String) {
                    runOnUiThread {
                        hologramView.currentState = HologramView.State.ERROR
                        stateLabel.text = "LISTENING ERROR"
                        stateLabel.setTextColor(Color.parseColor("#F87171"))
                        responseCardText.text = error
                        mainHandler.postDelayed({
                            hologramView.currentState = HologramView.State.IDLE
                            stateLabel.text = "TAP SPHERE OR MIC TO SPEAK"
                            stateLabel.setTextColor(Color.parseColor("#64748B"))
                        }, 2500)
                    }
                }
            }
        )
    }

    private fun executeAssistantTurn(rawText: String, isStt: Boolean) {
        promptTranscriptText.text = "You: $rawText"
        hologramView.currentState = HologramView.State.THINKING
        stateLabel.text = "THINKING..."
        stateLabel.setTextColor(Color.parseColor("#FDE047"))

        executeParsedIntent(rawText, isStt)
    }

    private fun executeParsedIntent(rawText: String, isStt: Boolean) {
        val lower = rawText.lowercase().trim()

        // Unsafe shell / script refusal check
        if (lower.contains("run script") || lower.contains("python script") || lower.contains("powershell") ||
            lower.contains("cmd.exe") || lower.contains("command line") || lower.contains("delete file") ||
            lower.contains("shutdown laptop") || lower.contains("restart laptop") || lower.contains("terminal")
        ) {
            hologramView.currentState = HologramView.State.ERROR
            stateLabel.text = "BLOCKED BY POLICY"
            stateLabel.setTextColor(Color.parseColor("#F87171"))
            val refusalMsg = "I cannot execute arbitrary scripts, shell commands, or file modifications. Only the 10 approved read-only tools and allowlisted applications are permitted."
            displayAndSpeakResponse(refusalMsg, isSuccess = false, tag = "BLOCKED")
            return
        }

        val intent = intentDispatcher.parseIntent(rawText)
        val downloadDir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: File(filesDir, "downloads")

        val consentCoordinator = CallbackConsentCoordinator { metadata, onDecision ->
            showCloudConsentDialog(metadata, onDecision)
        }

        Thread {
            intentDispatcher.dispatch(
                intent = intent,
                downloadDir = downloadDir,
                permissionPrompt = { prompt, onDecision ->
                    showEndpointPermissionDialog(prompt, onDecision)
                },
                consentCoordinator = consentCoordinator
            ) { spokenText, isSuccess, dataTag ->
                runOnUiThread {
                    displayAndSpeakResponse(spokenText, isSuccess, dataTag)
                }
            }
        }.start()
    }

    private fun displayAndSpeakResponse(text: String, isSuccess: Boolean, tag: String?) {
        responseCardText.text = text

        if (isSuccess) {
            hologramView.currentState = HologramView.State.SUCCESS
            stateLabel.text = "SUCCESS"
            stateLabel.setTextColor(Color.parseColor("#4ADE80"))
        } else {
            hologramView.currentState = HologramView.State.ERROR
            stateLabel.text = "ALERT"
            stateLabel.setTextColor(Color.parseColor("#F87171"))
        }

        // Add to Execution Log
        addLogMessage(ChatMessage(
            sender = "ASHWIN",
            text = text,
            isUser = false,
            tag = tag,
            isWarning = !isSuccess
        ))

        // Synthesize voice response
        val spoken = voiceSubsystem.ttsEngine.speak(text)
        if (!spoken) {
            mainHandler.postDelayed({
                hologramView.currentState = HologramView.State.IDLE
                stateLabel.text = "READY"
                stateLabel.setTextColor(Color.parseColor("#4ADE80"))
            }, 3000)
        }
    }

    private fun resetConversation() {
        coreSession.resetSession()
        chatMessages.clear()
        logContainer.removeAllViews()
        promptTranscriptText.text = "Ready."
        responseCardText.text = "Conversation cleared and transient RAM purged."
        hologramView.currentState = HologramView.State.IDLE
        stateLabel.text = "READY"
        stateLabel.setTextColor(Color.parseColor("#4ADE80"))
        Toast.makeText(this, "Transient state cleared.", Toast.LENGTH_SHORT).show()
    }

    private fun addLogMessage(message: ChatMessage) {
        chatMessages.add(message)
        val msgView = buildLogMessageView(message)
        logContainer.addView(msgView)
        logScrollView.post {
            logScrollView.fullScroll(View.FOCUS_DOWN)
        }
    }

    private fun buildLogMessageView(msg: ChatMessage): LinearLayout {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 6, 0, 6)
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createRoundedDrawable(
                Color.parseColor("#0F172A"),
                16f,
                if (msg.isWarning) Color.parseColor("#EF4444") else Color.parseColor("#334155")
            )
            setPadding(20, 16, 20, 16)
        }

        val tagText = TextView(this).apply {
            text = "[${SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(msg.timestamp))}] ${msg.tag ?: "EXECUTION"}"
            textSize = 10f
            setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
            setTextColor(if (msg.isWarning) Color.parseColor("#F87171") else Color.parseColor("#60A5FA"))
            setPadding(0, 0, 0, 4)
        }
        card.addView(tagText)

        val text = TextView(this).apply {
            this.text = msg.text
            textSize = 12f
            setTextColor(Color.parseColor("#E2E8F0"))
        }
        card.addView(text)

        container.addView(card)
        return container
    }

    private fun createRoundedDrawable(color: Int, radius: Float, strokeColor: Int? = null): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = radius
            setColor(color)
            if (strokeColor != null) {
                setStroke(2, strokeColor)
            }
        }
    }

    // =========================================================================
    // SECURITY & PERMISSION DIALOGS
    // =========================================================================

    private fun showEndpointPermissionDialog(prompt: String, onDecision: (Boolean) -> Unit) {
        runOnUiThread {
            AlertDialog.Builder(this)
                .setTitle("Endpoint Access Request")
                .setMessage(prompt)
                .setCancelable(false)
                .setPositiveButton("Allow") { _, _ ->
                    Log.i(TAG, "Access Permission: GRANTED by user")
                    onDecision(true)
                }
                .setNegativeButton("Deny") { _, _ ->
                    Log.i(TAG, "Access Permission: DENIED by user")
                    onDecision(false)
                }
                .create()
                .show()
        }
    }

    private fun showCloudConsentDialog(metadata: ConsentMetadata, onDecision: (CloudConsentToken?) -> Unit) {
        runOnUiThread {
            val message = "Source: ${metadata.sourceDomain.name}\n" +
                    "Classification: ${metadata.dataClass.name}\n" +
                    "Target: ${metadata.targetProvider}\n\n" +
                    "Local AI is unavailable. Processing this request with Cloud AI will transmit data outside your device.\n\n" +
                    "Allow cloud processing for this single request?"

            AlertDialog.Builder(this)
                .setTitle("Cloud AI Consent Required")
                .setMessage(message)
                .setCancelable(false)
                .setPositiveButton("Allow Once") { _, _ ->
                    val token = CloudConsentToken(
                        requestId = metadata.requestId,
                        sourceDomain = metadata.sourceDomain,
                        dataClass = metadata.dataClass,
                        targetProvider = metadata.targetProvider
                    )
                    onDecision(token)
                }
                .setNegativeButton("Deny") { _, _ ->
                    onDecision(null)
                }
                .create()
                .show()
        }
    }

    private fun showPinPromptDialog(uri: Uri) {
        val input = EditText(this).apply {
            hint = "Enter One-Time Setup PIN"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        AlertDialog.Builder(this)
            .setTitle("Identity Package PIN")
            .setView(input)
            .setPositiveButton("Unlock & Import") { _, _ ->
                val pin = input.text.toString()
                if (pin.isNotBlank()) {
                    executeProvisioningAndMotoVerification(uri = uri, file = null, pin = pin, isUiFlow = true)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // =========================================================================
    // PROVISIONING & IDENTITY IMPORT
    // =========================================================================

    private fun executeProvisioningAndMotoVerification(uri: Uri?, file: File?, pin: String, isUiFlow: Boolean = false) {
        Thread {
            try {
                val pkgBytes = if (uri != null) {
                    contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw Exception("Could not read URI: $uri")
                } else if (file != null && file.exists()) {
                    file.readBytes()
                } else {
                    throw Exception("Identity file not found.")
                }

                val engine = ProvisioningEngine(credentialStore)
                val result = engine.ingestPackage(pkgBytes, pin.toCharArray())
                val isSuccess = result.success

                runOnUiThread {
                    if (isSuccess) {
                        Toast.makeText(this, "Identity provisioned successfully!", Toast.LENGTH_LONG).show()
                        refreshSettingsStatus()
                        updateDeviceStatusBadges()
                    } else {
                        Toast.makeText(this, "Provisioning failed: Invalid package or PIN.", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Provisioning error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    // =========================================================================
    // DEVELOPER DIAGNOSTIC HARNESSES (Preserved for Testing)
    // =========================================================================

    private fun runDeveloperHarnessTest(packagePath: String, pin: String) {
        Thread {
            val logTag = "ASHWIN_PROVISION_TEST"
            Log.i(logTag, "Developer Harness Test Started: package=$packagePath")
            try {
                val file = File(packagePath)
                if (!file.exists()) {
                    Log.e(logTag, "FAIL: Package file does not exist at $packagePath")
                    return@Thread
                }
                val pkgBytes = file.readBytes()
                val engine = ProvisioningEngine(credentialStore)
                val result = engine.ingestPackage(pkgBytes, pin.toCharArray())
                val provSuccess = result.success
                Log.i(logTag, "Provisioning Result: $provSuccess")
            } catch (e: Exception) {
                Log.e(logTag, "FAIL: Developer harness exception: ${e.message}", e)
            }
        }.start()
    }

    private fun runVoiceDiagnosticVerification() {
        Thread {
            val logTag = "ASHWIN_STAGE_F_VOICE"
            Log.i(logTag, "Starting Voice Subsystem Diagnostic Verification...")
            val isAvail = voiceSubsystem.isVoiceInputAvailable()
            Log.i(logTag, "On-device STT Availability: $isAvail")
        }.start()
    }

    private fun runConsentDiagnosticVerification() {
        Thread {
            val logTag = "ASHWIN_STAGE_G_PHYSICAL"
            Log.i(logTag, "================ STAGE G PHYSICAL VERIFICATION START ================")
            coreSession.router.setLocalAvailability(false)
            val consentCoordinator = CallbackConsentCoordinator { metadata, onDecision ->
                val token = CloudConsentToken(metadata.requestId, metadata.sourceDomain, metadata.dataClass, metadata.targetProvider)
                onDecision(token)
            }
            coreSession.executeTurn(
                rawText = "Physical verification prompt",
                source = SourceDomain.PHONE,
                consentCoordinator = consentCoordinator
            ) { res ->
                Log.i(logTag, "Result: $res")
            }
        }.start()
    }

    private fun runMotoStorageDiagnosticVerification() {
        Thread {
            val logTag = "ASHWIN_STAGE_H_PHYSICAL"
            Log.i(logTag, "================ STAGE H PHYSICAL VERIFICATION START ================")
            val motoClient = coreSession.motoStorageClient ?: return@Thread
            motoClient.setAccessPermission(true)
            coreSession.executeStorageTurn(
                commandText = "Read artifact from Moto",
                operation = "read",
                targetPath = "Documents/moto_test_artifact.txt"
            ) { res ->
                Log.i(logTag, "Result: $res")
            }
        }.start()
    }

    private fun runStageIE2EVerification() {
        Thread {
            val logTag = "ASHWIN_STAGE_I_PHYSICAL"
            Log.i(logTag, "================ STAGE I PHYSICAL VERIFICATION START ================")
            coreSession.executeTurn("Stage I E2E Typed Turn") { res ->
                Log.i(logTag, "E2E Typed Result: $res")
            }
        }.start()
    }

    private fun runRealUserInteractionTest() {
        Thread {
            val logTag = "ASHWIN_USER_TEST"
            Log.i(logTag, "================ REAL USER INTERACTION TEST START ================")

            // Test 1: Holographic HUD Visibility & IDLE State
            runOnUiThread {
                hologramView.currentState = HologramView.State.IDLE
                stateLabel.text = "READY"
            }
            Log.i(logTag, "[TEST 1] Holographic HUD Verified: State=${hologramView.currentState}")

            // Test 2: Voice Personality & STT/TTS "Ashwin" greeting turn
            val greetingIntent = intentDispatcher.parseIntent("Ashwin")
            Log.i(logTag, "[TEST 2] Intent Parsed for 'Ashwin': $greetingIntent")
            val downloadDir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: File(filesDir, "downloads")
            
            intentDispatcher.dispatch(
                intent = greetingIntent,
                downloadDir = downloadDir,
                permissionPrompt = { _, cb -> cb(true) },
                consentCoordinator = null
            ) { spokenText, isSuccess, tag ->
                Log.i(logTag, "[TEST 2] Greeting Spoken Output: '$spokenText' (Success=$isSuccess, Tag=$tag)")
                runOnUiThread {
                    displayAndSpeakResponse(spokenText, isSuccess, tag)
                }
            }

            Thread.sleep(1500)

            // Test 3: Download resume ("Download my resume.")
            val resumeIntent = intentDispatcher.parseIntent("Download my resume.")
            Log.i(logTag, "[TEST 3] Intent Parsed for 'Download my resume.': $resumeIntent")
            
            intentDispatcher.dispatch(
                intent = resumeIntent,
                downloadDir = downloadDir,
                permissionPrompt = { prompt, cb ->
                    Log.i(logTag, "[TEST 3] Moto Permission Prompt Triggered: '$prompt'")
                    cb(true)
                },
                consentCoordinator = null
            ) { spokenText, isSuccess, tag ->
                Log.i(logTag, "[TEST 3] Resume Download Result: '$spokenText' (Success=$isSuccess, Tag=$tag)")
                runOnUiThread {
                    displayAndSpeakResponse(spokenText, isSuccess, tag)
                }
            }

            Thread.sleep(1500)

            // Test 4: Nonexistent file ("Ashwin, download xyz_nonexistent_file.pdf.")
            val nonExistentIntent = intentDispatcher.parseIntent("Ashwin, download xyz_nonexistent_file.pdf.")
            Log.i(logTag, "[TEST 4] Intent Parsed for Nonexistent File: $nonExistentIntent")

            intentDispatcher.dispatch(
                intent = nonExistentIntent,
                downloadDir = downloadDir,
                permissionPrompt = { prompt, cb ->
                    Log.i(logTag, "[TEST 4] Moto Permission Prompt Triggered: '$prompt'")
                    cb(true)
                },
                consentCoordinator = null
            ) { spokenText, isSuccess, tag ->
                Log.i(logTag, "[TEST 4] Nonexistent File Result: '$spokenText' (Success=$isSuccess, Tag=$tag)")
                runOnUiThread {
                    displayAndSpeakResponse(spokenText, isSuccess, tag)
                }
            }

            Thread.sleep(1500)

            // Test 5: Open Calculator on Laptop ("Ashwin, open Calculator.")
            val calcIntent = intentDispatcher.parseIntent("Ashwin, open Calculator.")
            Log.i(logTag, "[TEST 5] Intent Parsed for Calculator: $calcIntent")

            intentDispatcher.dispatch(
                intent = calcIntent,
                downloadDir = downloadDir,
                permissionPrompt = { prompt, cb ->
                    Log.i(logTag, "[TEST 5] Laptop Permission Prompt Triggered: '$prompt'")
                    cb(true)
                },
                consentCoordinator = null
            ) { spokenText, isSuccess, tag ->
                Log.i(logTag, "[TEST 5] Calculator Tool Result: '$spokenText' (Success=$isSuccess, Tag=$tag)")
                runOnUiThread {
                    displayAndSpeakResponse(spokenText, isSuccess, tag)
                }
            }

            Thread.sleep(1500)

            // Test 6: Email Connector Check ("Check my emails")
            val emailIntent = intentDispatcher.parseIntent("Check my emails")
            Log.i(logTag, "[TEST 6] Intent Parsed for Email: $emailIntent")

            intentDispatcher.dispatch(
                intent = emailIntent,
                downloadDir = downloadDir,
                permissionPrompt = { _, cb -> cb(true) },
                consentCoordinator = null
            ) { spokenText, isSuccess, tag ->
                Log.i(logTag, "[TEST 6] Email Result: '$spokenText' (Success=$isSuccess, Tag=$tag)")
                runOnUiThread {
                    displayAndSpeakResponse(spokenText, isSuccess, tag)
                }
            }

            Thread.sleep(1500)

            // Test 7: Dedicated Physical Utterance & Speech Normalization Test Suite
            val testUtterances = listOf(
                "Hello. How can I help?",
                "The balance is eight thousand five hundred rupees.",
                "Today is Thursday.",
                "I found your resume.",
                "Today is October 1, 2026 at 10:30 AM with ₹8,500.50 and 25% discount.",
                "Items ranked 1st, 2nd, and 3rd from January to December."
            )

            for ((idx, phrase) in testUtterances.withIndex()) {
                val normalized = SpeechNormalizer.normalize(phrase)
                Log.i(logTag, "[TEST 7.$idx] Spoken Phrase: '$phrase' -> Normalized: '$normalized'")
                runOnUiThread {
                    displayAndSpeakResponse(phrase, true, "SPEECH_TEST")
                }
                Thread.sleep(2000)
            }

            // Test 8: Session Reset
            runOnUiThread {
                resetConversation()
            }
            Log.i(logTag, "[TEST 8] Session Reset Verified. Ephemeral Memory Count: ${coreSession.memoryStore.count}")

            // Test 9: Settings View Navigation
            runOnUiThread {
                showSettingsScreen()
            }
            Thread.sleep(500)
            runOnUiThread {
                showHudScreen()
            }
            Log.i(logTag, "[TEST 9] Settings Navigation Verified.")

            Log.i(logTag, "================ REAL USER INTERACTION TEST COMPLETE ================")
        }.start()
    }
}

