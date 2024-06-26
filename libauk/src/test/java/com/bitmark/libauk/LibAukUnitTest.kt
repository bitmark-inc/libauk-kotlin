package com.bitmark.libauk

import com.bitmark.libauk.storage.WalletStorageImpl
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class LibAukUnitTest {

    private lateinit var libAuk: LibAuk

    @Before
    fun setUp() {
        libAuk = LibAuk.getInstance()
    }

    @Test
    fun calculateFirstEthAddress() {
        val words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        val passphrase = "feralfile"
        val expectedAddress = "0x459389605df56ea4bbb0f11f1b6d68928c73384a";
        val result = libAuk.calculateFirstEthAddress(words, passphrase);
        Assert.assertEquals(expectedAddress, result);
    }
}