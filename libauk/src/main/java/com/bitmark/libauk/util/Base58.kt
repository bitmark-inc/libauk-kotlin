package com.bitmark.libauk.util

object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private const val ENCODED_ZERO = '1'
    private const val BASE = 58

    fun encode(input: ByteArray): String {
        if (input.isEmpty()) return ""

        // Count leading zeros.
        var zeros = 0
        while (zeros < input.size && input[zeros] == 0.toByte()) {
            zeros++
        }

        // Convert base-256 digits to base-58 digits.
        val inputCopy = input.copyOf() // Copy input to avoid modifying original array
        val encoded = CharArray(input.size * 2) // Upper bound for encoded size
        var outputStart = encoded.size

        var inputStart = zeros
        while (inputStart < inputCopy.size) {
            encoded[--outputStart] = ALPHABET[divmod(inputCopy, inputStart, 256, BASE)]
            if (inputCopy[inputStart] == 0.toByte()) {
                inputStart++
            }
        }

        // Skip leading Base58 encoded zeros (1).
        while (outputStart < encoded.size && encoded[outputStart] == ENCODED_ZERO) {
            outputStart++
        }

        // Add the correct number of leading '1' characters for Base58.
        while (zeros-- > 0) {
            encoded[--outputStart] = ENCODED_ZERO
        }

        // Create the result string from the encoded char array.
        return String(encoded, outputStart, encoded.size - outputStart)
    }

    /**
     * Divides a byte array by a divisor in place, returning the remainder.
     */
    private fun divmod(number: ByteArray, startIndex: Int, base: Int, divisor: Int): Int {
        var remainder = 0
        for (i in startIndex until number.size) {
            val digit = (number[i].toInt() and 0xFF) + remainder * base
            number[i] = (digit / divisor).toByte()
            remainder = digit % divisor
        }
        return remainder
    }
}
