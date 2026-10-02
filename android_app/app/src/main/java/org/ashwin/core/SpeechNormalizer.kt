package org.ashwin.core

import java.util.regex.Pattern

/**
 * Deterministic On-Device Speech Normalizer.
 *
 * Expands numeric, currency, date, time, percentage, ordinal, and abbreviation tokens
 * into natural spoken English words before passing text to the TTS engine.
 *
 * Examples:
 * - "123" -> "one hundred twenty-three"
 * - "₹8500" / "₹8,500.50" -> "eight thousand five hundred rupees and fifty paise"
 * - "$50" / "$50.25" -> "fifty dollars and twenty-five cents"
 * - "10.5" -> "ten point five"
 * - "25%" -> "twenty-five percent"
 * - "1st" -> "first", "2nd" -> "second", "3rd" -> "third"
 * - "2026" -> "twenty twenty-six"
 * - "October 1, 2026" -> "October first, twenty twenty-six"
 * - "10:30 AM" -> "ten thirty a m"
 * - "Thursday" -> "Thursday"
 */
object SpeechNormalizer {

    private val ONES = arrayOf(
        "", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
        "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
        "seventeen", "eighteen", "nineteen"
    )

    private val TENS = arrayOf(
        "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"
    )

    private val ORDINALS_ONES = mapOf(
        1 to "first", 2 to "second", 3 to "third", 4 to "fourth", 5 to "fifth",
        6 to "sixth", 7 to "seventh", 8 to "eighth", 9 to "ninth", 10 to "tenth",
        11 to "eleventh", 12 to "twelfth", 13 to "thirteenth", 14 to "fourteenth",
        15 to "fifteenth", 16 to "sixteenth", 17 to "seventeenth", 18 to "eighteenth",
        19 to "nineteenth", 20 to "twentieth", 30 to "thirtieth", 40 to "fortieth",
        50 to "fiftieth", 60 to "sixtieth", 70 to "seventieth", 80 to "eightieth",
        90 to "ninetieth"
    )

    private val MONTHS = listOf(
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    )

    fun normalize(text: String): String {
        if (text.isBlank()) return ""

        var result = text

        // 1. Clean markdown links [label](url) -> label and formatting characters
        result = result.replace(Regex("\\[([^\\]]+)\\]\\([^\\)]+\\)"), "$1")
        result = result.replace(Regex("[*#`_]"), "")

        // 2. Remove commas from numbers: e.g. "8,500.50" -> "8500.50", "1,000,000" -> "1000000"
        result = result.replace(Regex("(?<=\\d),(?=\\d)"), "")

        // 3. Date format: e.g. "October 1, 2026", "October 1st 2026", "Oct 1, 2026"
        val monthsRegex = MONTHS.joinToString("|") { "(?:$it|${it.take(3)})" }
        result = result.replace(Regex("(?i)\\b($monthsRegex)\\s+(\\d{1,2})(?:st|nd|rd|th)?(?:,)?\\s+(\\d{4})\\b")) { match ->
            val month = match.groupValues[1]
            val day = match.groupValues[2].toLongOrNull() ?: 1L
            val year = match.groupValues[3].toIntOrNull() ?: 2026
            val fullMonth = MONTHS.firstOrNull { it.startsWith(month, ignoreCase = true) } ?: month
            "$fullMonth ${ordinalToWords(day)}, ${yearToWords(year)}"
        }

        // 4. Expand Currency: ₹8500 or ₹8500.50 or Rs. 8500 or 8500 INR
        result = result.replace(Regex("[₹]\\s*(\\d+(\\.\\d+)?)")) { match ->
            formatRupeeCurrency(match.groupValues[1])
        }
        result = result.replace(Regex("(?i)\\b(?:rs\\.?|inr)\\s*(\\d+(\\.\\d+)?)\\b")) { match ->
            formatRupeeCurrency(match.groupValues[1])
        }
        result = result.replace(Regex("[$]\\s*(\\d+(\\.\\d+)?)")) { match ->
            formatDollarCurrency(match.groupValues[1])
        }
        result = result.replace(Regex("(?i)\\b(\\d+(\\.\\d+)?)\\s*(?:rupees|rupee)\\b")) { match ->
            formatRupeeCurrency(match.groupValues[1])
        }
        result = result.replace(Regex("(?i)\\b(\\d+(\\.\\d+)?)\\s*(?:dollars|dollar)\\b")) { match ->
            formatDollarCurrency(match.groupValues[1])
        }

        // 5. Percentages: 25% or 25.5% -> twenty-five percent
        result = result.replace(Regex("(\\d+(?:\\.\\d+)?)\\s*%")) { match ->
            val num = match.groupValues[1]
            "${numberToSpokenWords(num)} percent"
        }

        // 6. Time format: 10:30 AM / 08:45 PM -> ten thirty a m
        result = result.replace(Regex("(?i)\\b(\\d{1,2}):(\\d{2})\\s*(am|pm)?\\b")) { match ->
            val hours = match.groupValues[1].toIntOrNull() ?: 0
            val minutes = match.groupValues[2].toIntOrNull() ?: 0
            val ampm = match.groupValues[3].uppercase()

            val hoursWord = integerToWords(hours.toLong())
            val minutesWord = if (minutes == 0) {
                if (ampm.isEmpty()) "o'clock" else ""
            } else if (minutes < 10) {
                "oh ${integerToWords(minutes.toLong())}"
            } else {
                integerToWords(minutes.toLong())
            }

            val ampmWord = when (ampm) {
                "AM" -> "a m"
                "PM" -> "p m"
                else -> ""
            }

            listOf(hoursWord, minutesWord, ampmWord).filter { it.isNotBlank() }.joinToString(" ")
        }

        // 7. Ordinals: 1st, 2nd, 3rd, 21st, 100th
        result = result.replace(Regex("(?i)\\b(\\d+)(st|nd|rd|th)\\b")) { match ->
            val num = match.groupValues[1].toLongOrNull() ?: 0L
            ordinalToWords(num)
        }

        // 8. 4-Digit Years: 1900-2099
        result = result.replace(Regex("\\b(19\\d{2}|20\\d{2})\\b")) { match ->
            val year = match.groupValues[1].toInt()
            yearToWords(year)
        }

        // 9. Decimals: 10.5 -> ten point five
        result = result.replace(Regex("\\b(\\d+)\\.(\\d+)\\b")) { match ->
            val intPart = match.groupValues[1].toLongOrNull() ?: 0L
            val decDigits = match.groupValues[2]
            val decWords = decDigits.map { digit ->
                ONES[digit.toString().toInt()]
            }.joinToString(" ")
            "${integerToWords(intPart)} point $decWords"
        }

        // 10. General Integers
        result = result.replace(Regex("\\b(\\d+)\\b")) { match ->
            val num = match.groupValues[1].toLongOrNull() ?: 0L
            integerToWords(num)
        }

        // 11. Common acronyms / technical terms expansion
        result = result.replace(Regex("(?i)\\bAM\\b"), "a m")
        result = result.replace(Regex("(?i)\\bPM\\b"), "p m")
        result = result.replace(Regex("(?i)\\bIP\\b"), "I P")
        result = result.replace(Regex("(?i)\\bUI\\b"), "U I")
        result = result.replace(Regex("(?i)\\bHUD\\b"), "H U D")
        result = result.replace(Regex("(?i)\\bPC\\b"), "P C")

        // Clean up whitespace
        return result.replace(Regex("\\s+"), " ").trim()
    }

    private fun formatRupeeCurrency(numStr: String): String {
        return if (numStr.contains(".")) {
            val parts = numStr.split(".")
            val intPart = parts[0].toLongOrNull() ?: 0L
            val decPartStr = parts.getOrNull(1) ?: "0"
            val decPart = (if (decPartStr.length == 1) decPartStr + "0" else decPartStr.take(2)).toLongOrNull() ?: 0L

            val rupeeWord = if (intPart == 1L) "one rupee" else "${integerToWords(intPart)} rupees"
            if (decPart > 0) {
                val paiseWord = if (decPart == 1L) "one paise" else "${integerToWords(decPart)} paise"
                "$rupeeWord and $paiseWord"
            } else {
                rupeeWord
            }
        } else {
            val num = numStr.toLongOrNull() ?: 0L
            if (num == 1L) "one rupee" else "${integerToWords(num)} rupees"
        }
    }

    private fun formatDollarCurrency(numStr: String): String {
        return if (numStr.contains(".")) {
            val parts = numStr.split(".")
            val intPart = parts[0].toLongOrNull() ?: 0L
            val decPartStr = parts.getOrNull(1) ?: "0"
            val decPart = (if (decPartStr.length == 1) decPartStr + "0" else decPartStr.take(2)).toLongOrNull() ?: 0L

            val dollarWord = if (intPart == 1L) "one dollar" else "${integerToWords(intPart)} dollars"
            if (decPart > 0) {
                val centWord = if (decPart == 1L) "one cent" else "${integerToWords(decPart)} cents"
                "$dollarWord and $centWord"
            } else {
                dollarWord
            }
        } else {
            val num = numStr.toLongOrNull() ?: 0L
            if (num == 1L) "one dollar" else "${integerToWords(num)} dollars"
        }
    }

    private fun numberToSpokenWords(numStr: String): String {
        return if (numStr.contains(".")) {
            val parts = numStr.split(".")
            val intPart = parts[0].toLongOrNull() ?: 0L
            val decPart = parts.getOrNull(1) ?: ""
            val decWords = decPart.map { ONES[it.toString().toInt()] }.joinToString(" ")
            "${integerToWords(intPart)} point $decWords"
        } else {
            val num = numStr.toLongOrNull() ?: 0L
            integerToWords(num)
        }
    }

    private fun yearToWords(year: Int): String {
        return when {
            year == 2000 -> "two thousand"
            year in 2001..2009 -> "two thousand ${ONES[year - 2000]}"
            year in 2010..2099 -> {
                val century = year / 100 // 20
                val lastTwo = year % 100
                if (lastTwo < 10) {
                    "${integerToWords(century.toLong())} oh ${integerToWords(lastTwo.toLong())}"
                } else {
                    "${integerToWords(century.toLong())} ${integerToWords(lastTwo.toLong())}"
                }
            }
            year in 1900..1999 -> {
                val century = year / 100 // 19
                val lastTwo = year % 100
                if (lastTwo == 0) {
                    "${integerToWords(century.toLong())} hundred"
                } else if (lastTwo < 10) {
                    "${integerToWords(century.toLong())} oh ${integerToWords(lastTwo.toLong())}"
                } else {
                    "${integerToWords(century.toLong())} ${integerToWords(lastTwo.toLong())}"
                }
            }
            else -> integerToWords(year.toLong())
        }
    }

    private fun ordinalToWords(number: Long): String {
        if (number <= 0) return number.toString()
        if (ORDINALS_ONES.containsKey(number.toInt())) {
            return ORDINALS_ONES[number.toInt()]!!
        }
        val lastTwoDigits = (number % 100).toInt()
        val lastDigit = (number % 10).toInt()

        if (lastTwoDigits in 11..19) {
            val base = integerToWords(number / 100 * 100)
            val suffix = ORDINALS_ONES[lastTwoDigits] ?: "${ONES[lastTwoDigits]}th"
            return if (base.isBlank()) suffix else "$base $suffix"
        }

        if (lastDigit != 0 && ORDINALS_ONES.containsKey(lastDigit)) {
            val baseNumber = number - lastDigit
            val base = integerToWords(baseNumber)
            val suffix = ORDINALS_ONES[lastDigit]!!
            return if (base.isBlank() || base == "zero") suffix else "$base-$suffix"
        }

        val cardinal = integerToWords(number)
        return if (cardinal.endsWith("y")) {
            cardinal.dropLast(1) + "ieth"
        } else {
            cardinal + "th"
        }
    }

    private fun integerToWords(number: Long): String {
        if (number == 0L) return "zero"
        if (number < 0) return "negative " + integerToWords(-number)

        var n = number
        val parts = mutableListOf<String>()

        if (n >= 1_000_000_000) {
            parts.add(convertChunk(n / 1_000_000_000) + " billion")
            n %= 1_000_000_000
        }
        if (n >= 1_000_000) {
            parts.add(convertChunk(n / 1_000_000) + " million")
            n %= 1_000_000
        }
        if (n >= 1_000) {
            parts.add(convertChunk(n / 1_000) + " thousand")
            n %= 1_000
        }
        if (n > 0) {
            parts.add(convertChunk(n))
        }

        return parts.joinToString(" ")
    }

    private fun convertChunk(number: Long): String {
        var n = number
        val parts = mutableListOf<String>()

        if (n >= 100) {
            parts.add(ONES[(n / 100).toInt()] + " hundred")
            n %= 100
        }
        if (n >= 20) {
            val tensWord = TENS[(n / 10).toInt()]
            val onesDigit = (n % 10).toInt()
            if (onesDigit > 0) {
                parts.add("$tensWord-${ONES[onesDigit]}")
            } else {
                parts.add(tensWord)
            }
        } else if (n > 0) {
            parts.add(ONES[n.toInt()])
        }

        return parts.joinToString(" ")
    }
}
