package org.ashwin.core

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

class ExtractorException(message: String) : Exception(message)

/**
 * ASHWIN Text Extractor & Validator (RULE-12, Section 9.3, Section 15).
 * Validates TXT content with strict size limits, binary signature rejection, encoding checks,
 * and control character bounds.
 */
object TextExtractor {
    const val MAX_SOURCE_SIZE = 5 * 1024 * 1024  // 5 MB
    const val MAX_TEXT_SIZE = 1 * 1024 * 1024    // 1 MB
    const val MAX_LINE_LENGTH = 64 * 1024        // 64 KB

    private val FORBIDDEN_SIGNATURES = listOf(
        byteArrayOf(0x4D, 0x5A),                                      // MZ (Windows EXE/DLL)
        byteArrayOf(0x7F, 0x45, 0x4C, 0x46),                         // \x7fELF (Linux ELF)
        byteArrayOf(0x50, 0x4B, 0x03, 0x04),                         // PK\x03\x04 (ZIP/JAR/APK)
        byteArrayOf(0x25, 0x50, 0x44, 0x46, 0x2D),                   // %PDF-
        byteArrayOf(0x1F, 0x8B.toByte()),                             // \x1f\x8b (GZIP)
        byteArrayOf(0x42, 0x5A, 0x68),                               // BZh (BZIP2)
        byteArrayOf(0xED.toByte(), 0xAB.toByte(), 0xA1.toByte(), 0xD7.toByte()) // RPM
    )

    private fun startsWith(data: ByteArray, prefix: ByteArray): Boolean {
        if (data.size < prefix.size) return false
        for (i in prefix.indices) {
            if (data[i] != prefix[i]) return false
        }
        return true
    }

    fun validateAndExtractTxt(contentBytes: ByteArray): String {
        if (contentBytes.size > MAX_SOURCE_SIZE) {
            throw ExtractorException("Source file size ${contentBytes.size} exceeds max limit $MAX_SOURCE_SIZE")
        }

        for (sig in FORBIDDEN_SIGNATURES) {
            if (startsWith(contentBytes, sig)) {
                throw ExtractorException("File contains forbidden binary signature.")
            }
        }

        val decodedText: String = if (contentBytes.size >= 2 &&
            ((contentBytes[0] == 0xFE.toByte() && contentBytes[1] == 0xFF.toByte()) ||
             (contentBytes[0] == 0xFF.toByte() && contentBytes[1] == 0xFE.toByte()))
        ) {
            try {
                String(contentBytes, StandardCharsets.UTF_16)
            } catch (e: Exception) {
                throw ExtractorException("Invalid UTF-16 encoding: ${e.message}")
            }
        } else {
            if (contentBytes.contains(0.toByte())) {
                throw ExtractorException("NUL byte detected in UTF-8 TXT content.")
            }
            try {
                val decoder = StandardCharsets.UTF_8.newDecoder()
                decoder.onMalformedInput(CodingErrorAction.REPORT)
                decoder.onUnmappableCharacter(CodingErrorAction.REPORT)
                decoder.decode(ByteBuffer.wrap(contentBytes)).toString()
            } catch (e: Exception) {
                throw ExtractorException("Invalid UTF-8 encoding: ${e.message}")
            }
        }

        val textByteCount = decodedText.toByteArray(StandardCharsets.UTF_8).size
        if (textByteCount > MAX_TEXT_SIZE) {
            throw ExtractorException("Extracted text size exceeds limit $MAX_TEXT_SIZE")
        }

        val allowedControls = setOf('\t', '\n', '\r', '\u000C')
        var controlCount = 0
        val totalChars = decodedText.length

        val lines = decodedText.lines()
        for (line in lines) {
            if (line.toByteArray(StandardCharsets.UTF_8).size > MAX_LINE_LENGTH) {
                throw ExtractorException("Line length ${line.length} exceeds max single line length $MAX_LINE_LENGTH")
            }
        }

        for (char in decodedText) {
            if (char.code < 32 && !allowedControls.contains(char)) {
                controlCount++
            }
        }

        if (totalChars > 0 && (controlCount.toDouble() / totalChars) > 0.01) {
            throw ExtractorException("Control character ratio exceeds 1% limit.")
        }

        return decodedText
    }
}
