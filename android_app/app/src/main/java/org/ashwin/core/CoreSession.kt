package org.ashwin.core

import android.util.Log
import java.util.UUID

class CoreSessionException(message: String) : Exception(message)

/**
 * ASHWIN Core Session Coordinator (Phase 3 / Stages A through H, Section 2, Section 5, Section 6, Section 10, Section 12).
 *
 * Coordinates execution lifecycle, storage connector binding, turn execution, and fail-closed state.
 */
class CoreSession(
    val credentialStore: CredentialStore,
    val scanner: SecretScanner = SecretScanner(),
    val memoryStore: EphemeralMemoryStore = EphemeralMemoryStore(scanner),
    val classifier: InputClassifier = InputClassifier(scanner),
    val router: AIRouter = AIRouter(),
    var motoStorageClient: MotoStorageClient? = null,
    var laptopConnector: LaptopConnector? = null
) {
    companion object {
        private const val TAG = "ASHWIN_CORE_SESSION"
        const val OFFLINE_STORAGE_MSG = "Your private storage server is currently unavailable."
        const val OFFLINE_LAPTOP_MSG = "Your Windows laptop endpoint is currently unavailable."
    }

    var sessionId: String = UUID.randomUUID().toString()
        private set
    var createdAt: Long = System.currentTimeMillis()
        private set
    var isActive: Boolean = true
        private set

    init {
        verifyHealth()
        Log.i(TAG, "CoreSession initialized: sessionId=$sessionId")
    }

    private fun verifyHealth() {
        val testScan = scanner.scanAndRedact("HEALTH_CHECK")
        if (testScan.second["healthy"] != true) {
            isActive = false
            throw CoreSessionException("CoreSession initialization failed: SecretScanner is unhealthy.")
        }
    }

    fun isHealthy(): Boolean {
        return isActive && (scanner.scanAndRedact("PING").second["healthy"] == true)
    }

    fun executeTurn(
        rawText: String,
        source: SourceDomain = SourceDomain.PHONE,
        isStt: Boolean = false,
        consentCoordinator: ConsentCoordinator? = null,
        callback: (Map<String, Any>) -> Unit
    ) {
        if (!isActive) {
            callback(mapOf("status" to "ERROR", "message" to "CoreSession is inactive. Ingress rejected."))
            return
        }

        // Step 1: Input Classification & Secret Scanning
        val classifiedContext: ScannedClassifiedContext
        try {
            classifiedContext = classifier.processUserInput(
                rawText = rawText,
                source = source,
                isStt = isStt
            )
        } catch (e: Exception) {
            Log.e(TAG, "Input classification rejected: ${e.message}")
            callback(mapOf(
                "status" to "BLOCKED",
                "message" to "RULE-03 / RULE-04 Violation: Classification failed closed: ${e.message}"
            ))
            return
        }

        // Step 2: Early Hard Fail-Closed for HIGHLY_PROTECTED (RULE-03)
        if (classifiedContext.dataClass == DataClass.HIGHLY_PROTECTED) {
            Log.e(TAG, "HIGHLY_PROTECTED data blocked before memory or model ingress.")
            callback(mapOf(
                "status" to "BLOCKED",
                "message" to "RULE-03 Violation: HIGHLY_PROTECTED data cannot enter memory or model context."
            ))
            return
        }

        // Step 3: Ephemeral RAM memory store insertion
        memoryStore.addContext(classifiedContext)

        // Step 4: First AIRouter execution attempt
        val routerResult = router.processContext(classifiedContext)

        if (routerResult["status"] == "SUCCESS") {
            callback(routerResult)
            return
        }

        // Step 5: Interactive Cloud Consent resolution
        val promptRequired = routerResult["user_prompt_required"] as? Boolean ?: false
        if (promptRequired && consentCoordinator != null) {
            val metadata = ConsentMetadata(
                sourceDomain = classifiedContext.source,
                dataClass = classifiedContext.dataClass,
                targetProvider = routerResult["target_provider"] as? String ?: "CloudAI",
                rationale = "Local AI is unavailable. Sending ${classifiedContext.dataClass.name} data from ${classifiedContext.source.name} to Cloud AI requires your explicit consent."
            )

            consentCoordinator.requestConsent(metadata) { consentToken ->
                if (consentToken != null) {
                    val secondResult = router.processContext(
                        context = classifiedContext,
                        consentToken = consentToken
                    )
                    callback(secondResult)
                } else {
                    callback(mapOf(
                        "status" to "DENIED",
                        "reason" to "Cloud AI consent was denied by user. Private data was not transmitted.",
                        "user_prompt_required" to false,
                        "data_class" to classifiedContext.dataClass.name,
                        "source" to classifiedContext.source.name,
                        "message" to "Cloud AI consent was denied by user. Private data was not transmitted."
                    ))
                }
            }
            return
        }

        callback(routerResult)
    }

    fun executeStorageTurn(
        commandText: String,
        operation: String,
        targetPath: String = "",
        permissionPromptCallback: ((String, (Boolean) -> Unit) -> Unit)? = null,
        consentCoordinator: ConsentCoordinator? = null,
        callback: (Map<String, Any>) -> Unit
    ) {
        if (!isActive) {
            callback(mapOf("status" to "ERROR", "message" to "CoreSession is inactive. Ingress rejected."))
            return
        }

        // Step 1: Ingest User Command as distinct PHONE context
        val userCmdContext = classifier.processUserInput(
            rawText = commandText,
            source = SourceDomain.PHONE,
            isStt = false
        )
        memoryStore.addContext(userCmdContext)

        val client = motoStorageClient
        if (client == null) {
            callback(mapOf(
                "status" to "OFFLINE",
                "message" to OFFLINE_STORAGE_MSG,
                "reason" to "No Moto storage client configured."
            ))
            return
        }

        // Step 2: Access Permission Check (Section 6.3) BEFORE any network/metadata query
        fun proceedWithStorageQuery() {
            val storageContext: ScannedClassifiedContext
            try {
                storageContext = when (operation) {
                    "list" -> client.listFiles(subfolder = targetPath)
                    "search" -> client.searchFiles(query = targetPath)
                    "read" -> client.readFile(relPath = targetPath)
                    else -> {
                        callback(mapOf("status" to "ERROR", "message" to "Unsupported storage operation: $operation"))
                        return
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Storage query failed: ${e.message}")
                val errStr = e.message ?: ""
                if (errStr.contains("Permission Denied") || errStr.contains("access permission", ignoreCase = true)) {
                    callback(mapOf("status" to "DENIED", "message" to errStr))
                } else {
                    callback(mapOf("status" to "OFFLINE", "message" to OFFLINE_STORAGE_MSG))
                }
                return
            }

            // Step 3: Insert verified ScannedClassifiedContext into Ephemeral Memory
            memoryStore.addContext(storageContext)

            // Step 4: Dispatch to AIRouter (sole boundary)
            val routerResult = router.processContext(storageContext)
            if (routerResult["status"] == "SUCCESS") {
                callback(routerResult)
                return
            }

            // Step 5: Interactive Cloud Consent resolution if local AI is unavailable
            val promptRequired = routerResult["user_prompt_required"] as? Boolean ?: false
            if (promptRequired && consentCoordinator != null) {
                val metadata = ConsentMetadata(
                    sourceDomain = storageContext.source,
                    dataClass = storageContext.dataClass,
                    targetProvider = routerResult["target_provider"] as? String ?: "CloudAI",
                    rationale = "Local AI is unavailable. Processing private Moto storage data with Cloud AI requires your explicit consent."
                )

                consentCoordinator.requestConsent(metadata) { consentToken ->
                    if (consentToken != null) {
                        val secondResult = router.processContext(
                            context = storageContext,
                            consentToken = consentToken
                        )
                        callback(secondResult)
                    } else {
                        callback(mapOf(
                            "status" to "DENIED",
                            "reason" to "Cloud AI consent was denied by user. Private storage data was not transmitted.",
                            "message" to "Cloud AI consent was denied by user. Private storage data was not transmitted."
                        ))
                    }
                }
                return
            }

            callback(routerResult)
        }

        if (!client.isAccessPermissionGranted()) {
            val promptText = "Your private Moto storage requires permission. May I access it?"
            if (permissionPromptCallback != null) {
                permissionPromptCallback(promptText) { granted ->
                    if (granted) {
                        client.setAccessPermission(true)
                        proceedWithStorageQuery()
                    } else {
                        callback(mapOf(
                            "status" to "DENIED",
                            "message" to "Moto storage access permission was denied. No storage data was retrieved."
                        ))
                    }
                }
            } else {
                callback(mapOf(
                    "status" to "DENIED",
                    "message" to "Moto storage access permission prompt unavailable."
                ))
            }
        } else {
            proceedWithStorageQuery()
        }
    }

    fun executeLaptopTurn(
        commandText: String,
        toolName: String,
        toolArgs: Map<String, Any> = emptyMap(),
        permissionPromptCallback: ((String, (Boolean) -> Unit) -> Unit)? = null,
        consentCoordinator: ConsentCoordinator? = null,
        callback: (Map<String, Any>) -> Unit
    ) {
        if (!isActive) {
            callback(mapOf("status" to "ERROR", "message" to "CoreSession is inactive. Ingress rejected."))
            return
        }

        // Step 1: Ingest User Command as distinct PHONE context
        val userCmdContext = classifier.processUserInput(
            rawText = commandText,
            source = SourceDomain.PHONE,
            isStt = false
        )
        memoryStore.addContext(userCmdContext)

        val connector = laptopConnector
        if (connector == null) {
            callback(mapOf(
                "status" to "OFFLINE",
                "message" to OFFLINE_LAPTOP_MSG,
                "reason" to "No LaptopConnector configured."
            ))
            return
        }

        fun proceedWithLaptopQuery() {
            val laptopContext: ScannedClassifiedContext
            try {
                laptopContext = connector.executeTool(toolName, toolArgs)
            } catch (e: Exception) {
                Log.e(TAG, "Laptop tool query failed: ${e.message}")
                val errStr = e.message ?: ""
                if (errStr.contains("Permission Denied", ignoreCase = true) || errStr.contains("access permission", ignoreCase = true)) {
                    callback(mapOf("status" to "DENIED", "message" to errStr))
                } else {
                    callback(mapOf("status" to "OFFLINE", "message" to OFFLINE_LAPTOP_MSG))
                }
                return
            }

            // Step 3: Insert verified ScannedClassifiedContext into Ephemeral Memory
            memoryStore.addContext(laptopContext)

            // Step 4: Dispatch to AIRouter (sole boundary)
            val routerResult = router.processContext(laptopContext)
            if (routerResult["status"] == "SUCCESS") {
                callback(routerResult)
                return
            }

            // Step 5: Interactive Cloud Consent resolution if local AI is unavailable
            val promptRequired = routerResult["user_prompt_required"] as? Boolean ?: false
            if (promptRequired && consentCoordinator != null) {
                val metadata = ConsentMetadata(
                    sourceDomain = laptopContext.source,
                    dataClass = laptopContext.dataClass,
                    targetProvider = routerResult["target_provider"] as? String ?: "CloudAI",
                    rationale = "Local AI is unavailable. Processing private Windows laptop data with Cloud AI requires your explicit consent."
                )

                consentCoordinator.requestConsent(metadata) { consentToken ->
                    if (consentToken != null) {
                        val secondResult = router.processContext(
                            context = laptopContext,
                            consentToken = consentToken
                        )
                        callback(secondResult)
                    } else {
                        callback(mapOf(
                            "status" to "DENIED",
                            "reason" to "Cloud AI consent was denied by user. Private laptop data was not transmitted.",
                            "message" to "Cloud AI consent was denied by user. Private laptop data was not transmitted."
                        ))
                    }
                }
                return
            }

            callback(routerResult)
        }

        if (!connector.isAccessPermissionGranted()) {
            val promptText = "Your Windows laptop requires permission to run '$toolName'. May I proceed?"
            if (permissionPromptCallback != null) {
                permissionPromptCallback(promptText) { granted ->
                    if (granted) {
                        connector.setAccessPermission(true)
                        proceedWithLaptopQuery()
                    } else {
                        callback(mapOf(
                            "status" to "DENIED",
                            "message" to "Windows laptop access permission was denied. No tool was executed."
                        ))
                    }
                }
            } else {
                callback(mapOf(
                    "status" to "DENIED",
                    "message" to "Windows laptop access permission prompt unavailable."
                ))
            }
        } else {
            proceedWithLaptopQuery()
        }
    }

    fun resetSession() {
        val oldSessionId = sessionId
        sessionId = UUID.randomUUID().toString()
        createdAt = System.currentTimeMillis()
        isActive = true
        memoryStore.clear()
        motoStorageClient?.setAccessPermission(false)
        laptopConnector?.setAccessPermission(false)
        verifyHealth()
        Log.i(TAG, "CoreSession reset: oldSessionId=$oldSessionId, newSessionId=$sessionId")
    }

    fun terminateSession() {
        isActive = false
        memoryStore.clear()
        motoStorageClient?.setAccessPermission(false)
        laptopConnector?.setAccessPermission(false)
        Log.i(TAG, "CoreSession terminated: sessionId=$sessionId")
    }
}
