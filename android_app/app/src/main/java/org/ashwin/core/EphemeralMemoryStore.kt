package org.ashwin.core

import java.util.UUID

/**
 * ASHWIN Bounded Ephemeral Short-Term Memory (Phase 3 / Stage E).
 * RAM-only, bounded FIFO retention in UTF-8 bytes and item count.
 * Strict secret scanning, classification inheritance, and Router-ingress gating (RULE-03, RULE-04, RULE-05).
 */

data class MemoryItem(
    val itemId: String,
    val content: String,
    val dataClass: DataClass,
    val source: SourceDomain,
    val timestamp: Long,
    val byteSize: Int,
    val metadata: Map<String, Any> = emptyMap(),
    val scanned: Boolean = true
)

class EphemeralMemoryStore(
    private val scanner: SecretScanner = SecretScanner(),
    val maxItems: Int = DEFAULT_MAX_ITEMS,
    val maxTotalBytes: Int = DEFAULT_MAX_TOTAL_BYTES
) {
    companion object {
        const val DEFAULT_MAX_ITEMS = 20
        const val DEFAULT_MAX_TOTAL_BYTES = 32_000
    }

    init {
        require(maxItems > 0) { "maxItems must be positive." }
        require(maxTotalBytes > 0) { "maxTotalBytes must be positive." }
    }

    private val items = mutableListOf<MemoryItem>()
    private var totalBytes = 0

    val count: Int
        get() = items.size

    val currentTotalBytes: Int
        get() = totalBytes

    fun addContext(context: ScannedClassifiedContext): MemoryItem {
        if (!context.scanned || context.scanSummary["healthy"] != true) {
            throw RouterGateException("RULE-04 Violation: Missing valid scan state.")
        }
        if (context.dataClass == DataClass.HIGHLY_PROTECTED) {
            throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter memory.")
        }

        return insertItem(
            content = context.content,
            dataClass = context.dataClass,
            source = context.source,
            metadata = context.metadata
        )
    }

    fun addUserInput(
        rawText: String,
        source: SourceDomain = SourceDomain.PHONE,
        isStt: Boolean = false,
        metadata: Map<String, Any> = emptyMap()
    ): MemoryItem {
        val (redactedContent, scanSummary, assessedClass) = scanner.scanAndRedact(rawText)

        if (scanSummary["healthy"] != true) {
            throw RouterGateException("Memory insertion rejected: SecretScanner is unhealthy.")
        }

        if (assessedClass == DataClass.HIGHLY_PROTECTED) {
            throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED material detected; blocked from memory.")
        }

        val enrichedMeta = metadata.toMutableMap().apply {
            put("input_type", if (isStt) "STT" else "TYPED_TEXT")
            put("redaction_count", scanSummary["redaction_count"] ?: 0)
        }

        return insertItem(
            content = redactedContent,
            dataClass = DataClass.PROTECTED,
            source = source,
            metadata = enrichedMeta
        )
    }

    private fun insertItem(
        content: String,
        dataClass: DataClass,
        source: SourceDomain,
        metadata: Map<String, Any>
    ): MemoryItem {
        if (dataClass == DataClass.HIGHLY_PROTECTED) {
            throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED data cannot be stored in memory.")
        }

        val utf8Bytes = content.toByteArray(Charsets.UTF_8)
        val byteSize = utf8Bytes.size

        val item = MemoryItem(
            itemId = UUID.randomUUID().toString(),
            content = content,
            dataClass = dataClass,
            source = source,
            timestamp = System.currentTimeMillis(),
            byteSize = byteSize,
            metadata = metadata,
            scanned = true
        )

        items.add(item)
        totalBytes += byteSize

        evictExcess()
        return item
    }

    private fun evictExcess() {
        while (items.size > maxItems) {
            val evicted = items.removeAt(0)
            totalBytes -= evicted.byteSize
        }
        while (totalBytes > maxTotalBytes && items.isNotEmpty()) {
            val evicted = items.removeAt(0)
            totalBytes -= evicted.byteSize
        }
    }

    fun recallContext(maxItemsToRecall: Int? = null): ScannedClassifiedContext {
        if (items.isEmpty()) {
            return ScannedClassifiedContext(
                content = "",
                dataClass = DataClass.PUBLIC,
                source = SourceDomain.PHONE,
                scanned = true,
                scanSummary = mapOf("healthy" to true, "memory_items_count" to 0),
                metadata = mapOf("recalled_items_count" to 0)
            )
        }

        val recalled = if (maxItemsToRecall != null) {
            items.takeLast(maxItemsToRecall)
        } else {
            items.toList()
        }

        var hasHighlyProtected = false
        var hasProtected = false
        var hasPersonal = false

        val texts = mutableListOf<String>()
        for (it in recalled) {
            if (!it.scanned) {
                throw RouterGateException("RULE-04 Violation: Unscanned item found in memory store.")
            }
            when (it.dataClass) {
                DataClass.HIGHLY_PROTECTED -> hasHighlyProtected = true
                DataClass.PROTECTED -> hasProtected = true
                DataClass.PERSONAL -> hasPersonal = true
                DataClass.PUBLIC -> {}
            }
            texts.add(it.content)
        }

        if (hasHighlyProtected) {
            throw SecurityViolationException("RULE-03 Violation: HIGHLY_PROTECTED item encountered during memory recall.")
        }

        val inheritedClass = when {
            hasProtected -> DataClass.PROTECTED
            hasPersonal -> DataClass.PERSONAL
            else -> DataClass.PUBLIC
        }

        val combinedContent = texts.joinToString("\n")

        return ScannedClassifiedContext(
            content = combinedContent,
            dataClass = inheritedClass,
            source = SourceDomain.PHONE,
            scanned = true,
            scanSummary = mapOf(
                "healthy" to true,
                "memory_items_count" to recalled.size
            ),
            metadata = mapOf(
                "recalled_items_count" to recalled.size,
                "total_memory_bytes" to recalled.sumOf { it.byteSize }
            )
        )
    }

    fun getItems(): List<MemoryItem> = items.toList()

    fun clear() {
        items.clear()
        totalBytes = 0
    }

    fun reset() {
        clear()
    }
}
