package com.bitmark.libauk

import org.web3j.crypto.Bip32ECKeyPair

object Const {
    val BITMARK_DERIVATION_PATH = "m/44\'/731\'/0\'/0/0"

    // m/44'/731'/1'/0/0
    val ACCOUNT_DERIVATION_PATH = intArrayOf(
        44 or Bip32ECKeyPair.HARDENED_BIT,
        731 or Bip32ECKeyPair.HARDENED_BIT,
        1 or Bip32ECKeyPair.HARDENED_BIT,
        0,
        0
    )
}