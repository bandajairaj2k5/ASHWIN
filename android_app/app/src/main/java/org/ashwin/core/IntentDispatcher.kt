package org.ashwin.core

import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * Intent Representation for Deterministic AI Execution
 */
sealed class AssistantIntent {
    // Moto G3 Private Storage
    data class MotoDownload(val fileName: String) : AssistantIntent()
    data class MotoSearch(val query: String) : AssistantIntent()
    data class MotoList(val subfolder: String = "") : AssistantIntent()
    data class MotoRead(val fileName: String) : AssistantIntent()

    // Windows Laptop 10 Tools
    data class LaptopOpenApp(val appName: String) : AssistantIntent()
    data class LaptopFindFile(val query: String) : AssistantIntent()
    data class LaptopFindFolder(val query: String) : AssistantIntent()
    data class LaptopReadDocument(val relPath: String) : AssistantIntent()
    data class LaptopListDirectory(val relPath: String) : AssistantIntent()
    data class LaptopViewDocument(val relPath: String) : AssistantIntent()
    data class LaptopOpenFolder(val relPath: String) : AssistantIntent()
    object LaptopSystemStatus : AssistantIntent()
    data class LaptopProcessStatus(val processName: String) : AssistantIntent()

    // Email Connector
    object EmailCheckUnread : AssistantIntent()
    data class EmailListRecent(val limit: Int = 5) : AssistantIntent()
    data class EmailRead(val emailId: String) : AssistantIntent()
    data class EmailSearch(val query: String) : AssistantIntent()

    // General On-Device Capabilities
    object Greeting : AssistantIntent()
    object Capabilities : AssistantIntent()
    object SystemTime : AssistantIntent()
    data class GeneralQuery(val query: String) : AssistantIntent()
}

/**
 * Intent Dispatcher & Parser.
 *
 * Deterministically parses natural language user speech or text without requiring
 * external paid AI APIs. Strictly fails closed or reports honest capability boundaries.
 */
class IntentDispatcher(
    val session: CoreSession,
    val emailConnector: EmailConnector
) {
    companion object {
        private const val TAG = "ASHWIN_INTENT_DISPATCHER"
    }

    fun parseIntent(input: String): AssistantIntent {
        var text = input.trim()
        // Strip leading wake words: "Ashwin,", "Ashwin:", "Ashwin ", "Hey Ashwin,"
        text = text.replace(Regex("^(hey\\s+)?ashwin[,:\\s]*\\s*", RegexOption.IGNORE_CASE), "").trim()

        if (text.isBlank() || text.equals("ashwin", ignoreCase = true) || text.equals("hello", ignoreCase = true) || text.equals("hi", ignoreCase = true) || text.equals("hey", ignoreCase = true)) {
            return AssistantIntent.Greeting
        }

        // Clean trailing punctuation
        val cleanText = text.trimEnd('.', '?', '!', ',', ';')
        val lower = cleanText.lowercase(Locale.US)

        // 1. Email Intents
        if (lower.contains("unread email") || lower.contains("how many emails") || lower == "check email" || lower == "check emails" || lower == "check my email" || lower == "check my emails") {
            return AssistantIntent.EmailCheckUnread
        }
        if (lower.startsWith("list email") || lower.startsWith("recent email") || lower.startsWith("show emails") || lower.startsWith("show my emails")) {
            return AssistantIntent.EmailListRecent(5)
        }
        if (lower.startsWith("search email") || lower.startsWith("find email")) {
            val q = cleanText.replace(Regex("^(search|find)\\s+(emails?|mail)\\s+(for\\s+|about\\s+)?", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.EmailSearch(q)
        }
        if (lower.startsWith("read email")) {
            val q = cleanText.replace(Regex("^read\\s+(email|mail)\\s+", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.EmailRead(q)
        }

        // 2. Windows Laptop Endpoint Intents (10 Tools)
        if (lower.contains("calculator") && (lower.contains("open") || lower.contains("launch") || lower.contains("start"))) {
            return AssistantIntent.LaptopOpenApp("calc.exe")
        }
        if (lower.contains("notepad") && (lower.contains("open") || lower.contains("launch") || lower.contains("start"))) {
            return AssistantIntent.LaptopOpenApp("notepad.exe")
        }
        if (lower.contains("laptop status") || lower.contains("pc status") || lower.contains("computer status") || lower.contains("system status")) {
            return AssistantIntent.LaptopSystemStatus
        }
        if (lower.startsWith("find file on laptop") || lower.startsWith("search file on laptop") || lower.startsWith("find laptop file")) {
            val q = cleanText.replace(Regex("^(find|search)\\s+(file|document)?\\s*(on\\s+laptop|on\\s+pc|laptop)?\\s*", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.LaptopFindFile(q)
        }
        if (lower.startsWith("find folder on laptop") || lower.startsWith("search folder on laptop")) {
            val q = cleanText.replace(Regex("^(find|search)\\s+folder\\s*(on\\s+laptop|on\\s+pc)?\\s*", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.LaptopFindFolder(q)
        }
        if (lower.startsWith("read laptop doc") || lower.startsWith("read laptop document")) {
            val q = cleanText.replace(Regex("^read\\s+laptop\\s+(doc|document|file)\\s*", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.LaptopReadDocument(q)
        }

        // 3. Moto G3 Storage Intents
        if (lower.startsWith("download") || lower.startsWith("save to phone") || lower.startsWith("get file")) {
            val fn = cleanText.replace(Regex("^(download|save to phone|get file)\\s+(my\\s+)?", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.MotoDownload(fn)
        }
        if (lower.startsWith("is ") && (lower.contains("available") || lower.contains("present") || lower.contains("on moto") || lower.contains("on storage"))) {
            val fn = cleanText.replace(Regex("^is\\s+(my\\s+)?", RegexOption.IGNORE_CASE), "")
                .replace(Regex("\\s+(available|present|on moto|on storage)\\??$", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.MotoSearch(fn)
        }
        if (lower.startsWith("find ") || lower.startsWith("search ") || lower.startsWith("locate ")) {
            val q = cleanText.replace(Regex("^(find|search|locate)\\s+(my\\s+)?", RegexOption.IGNORE_CASE), "")
                .replace(Regex("\\s+(on moto|in storage)$", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.MotoSearch(q)
        }
        if (lower.contains("list files") || lower.contains("show files") || lower.contains("what files") || lower == "files") {
            return AssistantIntent.MotoList()
        }
        if (lower.startsWith("read ") || lower.startsWith("open ")) {
            val fn = cleanText.replace(Regex("^(read|open)\\s+(my\\s+)?", RegexOption.IGNORE_CASE), "").trim()
            return AssistantIntent.MotoRead(fn)
        }

        // 4. General Conversational & Assistant Intents
        if (lower.contains("what can you do") || lower.contains("help") || lower.contains("capabilities") || lower.contains("who are you")) {
            return AssistantIntent.Capabilities
        }
        if (lower.contains("time") || lower.contains("date") || lower.contains("day is it") || lower.contains("what day")) {
            return AssistantIntent.SystemTime
        }

        return AssistantIntent.GeneralQuery(cleanText)
    }

    /**
     * Dispatch intent and produce human-spoken and visual response.
     */
    fun dispatch(
        intent: AssistantIntent,
        downloadDir: File,
        permissionPrompt: (String, (Boolean) -> Unit) -> Unit,
        consentCoordinator: ConsentCoordinator?,
        onResult: (spokenText: String, isSuccess: Boolean, dataTag: String?) -> Unit
    ) {
        when (intent) {
            is AssistantIntent.MotoDownload -> {
                val client = session.motoStorageClient
                if (client == null || !client.isPaired()) {
                    onResult("Your storage is currently offline.", false, "MOTO_STORAGE")
                    return
                }

                fun executeDownload() {
                    try {
                        val result = client.downloadFileToLocal(intent.fileName, downloadDir)
                        if (result.success) {
                            onResult("Downloaded ${intent.fileName} to your phone.", true, "DOWNLOAD")
                        } else {
                            if (result.message.contains("not found", ignoreCase = true)) {
                                onResult("I couldn't find that file in your storage.", true, "MOTO_STORAGE")
                            } else {
                                onResult(result.message, false, "DOWNLOAD_ERROR")
                            }
                        }
                    } catch (e: Exception) {
                        val msg = e.message ?: ""
                        if (msg.contains("not found", ignoreCase = true)) {
                            onResult("I couldn't find that file in your storage.", true, "MOTO_STORAGE")
                        } else {
                            onResult("Could not download ${intent.fileName}: $msg", false, "DOWNLOAD_ERROR")
                        }
                    }
                }

                if (!client.isAccessPermissionGranted()) {
                    permissionPrompt("Allow ASHWIN to access your Moto G3 storage to download '${intent.fileName}'?") { granted ->
                        if (granted) {
                            client.setAccessPermission(true)
                            executeDownload()
                        } else {
                            onResult("Storage access permission was denied.", false, "DENIED")
                        }
                    }
                } else {
                    executeDownload()
                }
            }

            is AssistantIntent.MotoSearch -> {
                session.executeStorageTurn(
                    commandText = "Search for ${intent.query}",
                    operation = "search",
                    targetPath = intent.query,
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: ""
                        if (resp.contains("No matching files found") || resp.isBlank()) {
                            onResult("I couldn't find that file in your storage.", true, "MOTO_STORAGE")
                        } else {
                            onResult("Found matching files in storage:\n$resp", true, "MOTO_STORAGE")
                        }
                    } else {
                        val msg = res["message"] as? String ?: "Storage query failed."
                        onResult(msg, false, "MOTO_STORAGE")
                    }
                }
            }

            is AssistantIntent.MotoList -> {
                session.executeStorageTurn(
                    commandText = "List storage files",
                    operation = "list",
                    targetPath = intent.subfolder,
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: ""
                        onResult("Here are the files in your storage:\n$resp", true, "MOTO_STORAGE")
                    } else {
                        val msg = res["message"] as? String ?: "Storage listing failed."
                        onResult(msg, false, "MOTO_STORAGE")
                    }
                }
            }

            is AssistantIntent.MotoRead -> {
                session.executeStorageTurn(
                    commandText = "Read file ${intent.fileName}",
                    operation = "read",
                    targetPath = intent.fileName,
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: ""
                        onResult("Contents of ${intent.fileName}:\n$resp", true, "MOTO_STORAGE")
                    } else {
                        val msg = res["message"] as? String ?: "Storage read failed."
                        onResult(msg, false, "MOTO_STORAGE")
                    }
                }
            }

            is AssistantIntent.LaptopOpenApp -> {
                session.executeLaptopTurn(
                    commandText = "Open ${intent.appName}",
                    toolName = "open_allowed_app",
                    toolArgs = mapOf("app_name" to intent.appName),
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val appLabel = if (intent.appName.contains("calc")) "Calculator" else "Notepad"
                        onResult("Opened $appLabel on your laptop.", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "Failed to open app on laptop."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.LaptopSystemStatus -> {
                session.executeLaptopTurn(
                    commandText = "Get system status",
                    toolName = "get_system_status",
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: "Laptop system operational."
                        onResult("Windows Laptop Status:\n$resp", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "Laptop status query failed."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.LaptopFindFile -> {
                session.executeLaptopTurn(
                    commandText = "Find file ${intent.query}",
                    toolName = "find_file",
                    toolArgs = mapOf("query" to intent.query, "search_dir" to "documents"),
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: ""
                        onResult("Laptop search results for '${intent.query}':\n$resp", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "Laptop file search failed."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.LaptopFindFolder -> {
                session.executeLaptopTurn(
                    commandText = "Find folder ${intent.query}",
                    toolName = "find_folder",
                    toolArgs = mapOf("query" to intent.query),
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: ""
                        onResult("Laptop folders matching '${intent.query}':\n$resp", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "Laptop folder search failed."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.LaptopReadDocument -> {
                session.executeLaptopTurn(
                    commandText = "Read document ${intent.relPath}",
                    toolName = "read_document_text",
                    toolArgs = mapOf("rel_path" to intent.relPath),
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: ""
                        onResult("Document content from laptop:\n$resp", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "Laptop read failed."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.LaptopProcessStatus -> {
                session.executeLaptopTurn(
                    commandText = "Check process ${intent.processName}",
                    toolName = "check_process_status",
                    toolArgs = mapOf("process_name" to intent.processName),
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: ""
                        onResult("Process status: $resp", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "Process check failed."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.LaptopListDirectory -> {
                session.executeLaptopTurn(
                    commandText = "List directory ${intent.relPath}",
                    toolName = "list_allowed_directory",
                    toolArgs = mapOf("rel_path" to intent.relPath),
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val resp = res["response"] as? String ?: ""
                        onResult("Directory contents:\n$resp", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "Directory listing failed."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.LaptopViewDocument -> {
                session.executeLaptopTurn(
                    commandText = "View document ${intent.relPath}",
                    toolName = "view_document",
                    toolArgs = mapOf("rel_path" to intent.relPath),
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        onResult("Document opened in viewer on laptop.", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "View document failed."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.LaptopOpenFolder -> {
                session.executeLaptopTurn(
                    commandText = "Open folder ${intent.relPath}",
                    toolName = "open_folder",
                    toolArgs = mapOf("rel_path" to intent.relPath),
                    permissionPromptCallback = permissionPrompt,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        onResult("Folder opened on laptop.", true, "LAPTOP")
                    } else {
                        val msg = res["message"] as? String ?: "Open folder failed."
                        if (msg.contains("unavailable", ignoreCase = true) || msg.contains("not paired", ignoreCase = true)) {
                            onResult("Your laptop is offline.", false, "LAPTOP_ERROR")
                        } else {
                            onResult(msg, false, "LAPTOP_ERROR")
                        }
                    }
                }
            }

            is AssistantIntent.EmailCheckUnread -> {
                if (!emailConnector.isConfigured()) {
                    onResult("Your email isn't connected yet.", false, "EMAIL_UNCONFIGURED")
                    return
                }
                val unreadCount = emailConnector.getUnreadCount()
                val recent = emailConnector.listRecentEmails(3)
                val summary = if (unreadCount > 0) {
                    val titles = recent.joinToString("\n") { "• ${it.sender}: ${it.subject}" }
                    "You have $unreadCount unread emails:\n$titles"
                } else {
                    "You have no unread emails."
                }
                onResult(summary, true, "EMAIL")
            }

            is AssistantIntent.EmailListRecent -> {
                if (!emailConnector.isConfigured()) {
                    onResult("Your email isn't connected yet.", false, "EMAIL_UNCONFIGURED")
                    return
                }
                val emails = emailConnector.listRecentEmails(intent.limit)
                val summary = emails.joinToString("\n\n") {
                    "[${it.date}] From: ${it.sender}\nSubject: ${it.subject}\n${it.previewSnippet}"
                }
                onResult(summary, true, "EMAIL")
            }

            is AssistantIntent.EmailSearch -> {
                if (!emailConnector.isConfigured()) {
                    onResult("Your email isn't connected yet.", false, "EMAIL_UNCONFIGURED")
                    return
                }
                val emails = emailConnector.searchEmails(intent.query)
                if (emails.isEmpty()) {
                    onResult("No emails matching '${intent.query}' were found.", true, "EMAIL")
                } else {
                    val summary = emails.joinToString("\n") { "• [${it.date}] ${it.sender}: ${it.subject}" }
                    onResult("Found ${emails.size} matching emails:\n$summary", true, "EMAIL")
                }
            }

            is AssistantIntent.EmailRead -> {
                if (!emailConnector.isConfigured()) {
                    onResult("Your email isn't connected yet.", false, "EMAIL_UNCONFIGURED")
                    return
                }
                try {
                    val ctx = emailConnector.readEmail(intent.emailId)
                    onResult("Email Details:\n${ctx.content}", true, "EMAIL")
                } catch (e: Exception) {
                    onResult("Could not read email: ${e.message}", false, "EMAIL_ERROR")
                }
            }

            is AssistantIntent.Greeting -> {
                onResult("Hello. How can I help?", true, "GREETING")
            }

            is AssistantIntent.Capabilities -> {
                val caps = "I am ASHWIN, designed for secure personal computing:\n" +
                        "• Moto G3 Storage: Download and search your private encrypted files.\n" +
                        "• Windows Endpoint: Launch allowed tools, search documents, and inspect laptop status.\n" +
                        "• Email Briefings: Check unread mail and search messages in read-only mode.\n" +
                        "• Voice Interface: Fully offline on-device speech synthesis and recognition."
                onResult(caps, true, "CAPABILITIES")
            }

            is AssistantIntent.SystemTime -> {
                val now = SimpleDateFormat("EEEE, MMMM dd, yyyy 'at' hh:mm a", Locale.US).format(Date())
                onResult("The current time is $now.", true, "TIME")
            }

            is AssistantIntent.GeneralQuery -> {
                // Route through CoreSession's executeTurn
                session.executeTurn(
                    rawText = intent.query,
                    source = SourceDomain.PHONE,
                    isStt = false,
                    consentCoordinator = consentCoordinator
                ) { res ->
                    val status = res["status"] as? String
                    if (status == "SUCCESS") {
                        val responseText = res["response"] as? String ?: ""
                        onResult(responseText, true, "GENERAL")
                    } else {
                        val msg = res["message"] as? String ?: "Local AI model is not installed yet. Operating in deterministic on-device mode."
                        onResult(msg, false, "GENERAL_INFO")
                    }
                }
            }
        }
    }
}
