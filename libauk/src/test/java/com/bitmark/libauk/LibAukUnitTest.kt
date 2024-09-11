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

    @Test
    fun testGetAccountDID {
        val words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        libAuk.importKey(words);

        val expectedDiD = "did:key:zQ3shUnBWE7Dkskaozsnzsb78kVcgQFbtXf7zdCCDN3qepBGL";
        val expectedSig = "3045022100bcab09830ca590e641db881d9642ea2372cecedc1a37647e9d6ab8365521b7c0022041cba853b76596a64baf909aa311a18ae4d79c88aec15a080a897e3266e44aa2"
        val accountDID = libAuk.getAccountDID();
        val sig = libAuk.getAccountDIDSignature("hello");
        Assert.assertEquals(expectedAddress, result);
    }
}