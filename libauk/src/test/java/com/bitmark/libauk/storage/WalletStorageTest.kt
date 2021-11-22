package com.bitmark.libauk.storage

import com.bitmark.libauk.model.Seed
import com.bitmark.libauk.util.newGsonInstance
import com.nhaarman.mockitokotlin2.*
import org.junit.Before
import org.junit.Test
import org.web3j.crypto.MnemonicUtils
import org.web3j.crypto.RawTransaction
import java.math.BigInteger
import java.util.*

class WalletStorageTest {

    private lateinit var walletStorage: WalletStorage
    private val secureFileStorage: SecureFileStorage = mock()

    @Before
    fun setUp() {
        walletStorage = WalletStorageImpl(secureFileStorage)
    }

    @Test
    fun createKey() {
        given(secureFileStorage.isExisting(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            false
        )
        given(secureFileStorage.isExisting(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            false
        )
        doNothing().`when`(secureFileStorage).writeOnFilesDir(any(), any())

        walletStorage.createKey(name = "Hello").test()
            .assertComplete()
    }

    @Test
    fun createKeyExistingError() {
        given(secureFileStorage.isExisting(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExisting(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            true
        )

        walletStorage.createKey(name = "Hello")
            .test()
            .assertError {
                it.message == "Wallet is already created!"
            }
    }

    @Test
    fun importKey() {
        val words = listOf("victory", "fatigue", "diet", "funny", "senior", "coral", "motion", "canal", "leg", "elite", "hen", "model")

        given(secureFileStorage.isExisting(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            false
        )
        given(secureFileStorage.isExisting(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            false
        )
        doNothing().`when`(secureFileStorage).writeOnFilesDir(any(), any())

        walletStorage.importKey(words = words, name = "Hello", creationDate = Date())
            .test()
            .assertComplete()
    }

    @Test
    fun importKeyExistingError() {
        val words = listOf("victory", "fatigue", "diet", "funny", "senior", "coral", "motion", "canal", "leg", "elite", "hen", "model")

        given(secureFileStorage.isExisting(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExisting(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            true
        )

        walletStorage.importKey(words = words, name = "Hello", creationDate = Date())
            .test()
            .assertError {
                it.message == "Wallet is already created!"
            }
    }

    @Test
    fun isWalletCreated() {
        given(secureFileStorage.isExisting(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExisting(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            true
        )

        walletStorage.isWalletCreated()
            .test()
            .assertComplete()
            .assertResult(true)
    }

    @Test
    fun getETHAddress() {
        val info =
            "{\"ethAddress\":\"0xf9631da81e6c93c0976e7af6c3c2b725639260f6\",\"creationDate\":\"Sep 20, 2021 11:17:08 AM\"}"
        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            info.toByteArray()
        )

        walletStorage.getETHAddress()
            .test()
            .assertComplete()
            .assertResult("0xf9631da81e6c93c0976e7af6c3c2b725639260f6")
    }

    @Test
    fun signPersonalMessage() {
        val words = "victory fatigue diet funny senior coral motion canal leg elite hen model"
        val entropy = MnemonicUtils.generateEntropy(words)
        val seed = Seed(entropy, Date(), "Test")
        val seedString = newGsonInstance().toJson(seed)

        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            seedString.toByteArray()
        )

        walletStorage.signPersonalMessage("hello".toByteArray())
            .test()
            .assertComplete()
    }

    @Test
    fun signTransaction() {
        val words = "victory fatigue diet funny senior coral motion canal leg elite hen model"
        val entropy = MnemonicUtils.generateEntropy(words)
        val seed = Seed(entropy, Date(), "Test")
        val seedString = newGsonInstance().toJson(seed)

        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            seedString.toByteArray()
        )

        val transaction = RawTransaction.createEtherTransaction(
            BigInteger.ONE,
            BigInteger.ONE,
            BigInteger.ONE,
            "0xf9631da81e6c93c0976e7af6c3c2b725639260f6",
            BigInteger.ONE
        )
        walletStorage.signTransaction(transaction, chainId = 1)
            .test()
            .assertComplete()
    }

    @Test
    fun exportSeed() {
        val words = "victory fatigue diet funny senior coral motion canal leg elite hen model"
        val entropy = MnemonicUtils.generateEntropy(words)
        val seed = Seed(entropy, Date(), "Test")
        val seedString = newGsonInstance().toJson(seed)

        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            seedString.toByteArray()
        )

        walletStorage.exportMnemonicWords()
            .test()
            .assertResult(
                "victory fatigue diet funny senior coral motion canal leg elite hen model"
            )
    }

    @Test
    fun removeKeys() {
        given(secureFileStorage.isExisting(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExisting(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            true
        )
        doNothing().`when`(secureFileStorage).writeOnFilesDir(any(), any())

        walletStorage.removeKeys()
            .test()
            .assertComplete()
    }

    @Test
    fun removeKeysError() {
        given(secureFileStorage.isExisting(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            false
        )
        given(secureFileStorage.isExisting(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            false
        )

        walletStorage.removeKeys()
            .test()
            .assertError {
                it.message == "Wallet is not created!"
            }
    }
}