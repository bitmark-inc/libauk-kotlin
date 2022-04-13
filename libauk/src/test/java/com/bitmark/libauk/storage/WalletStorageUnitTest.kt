package com.bitmark.libauk.storage

import com.bitmark.libauk.model.Seed
import com.bitmark.libauk.util.newGsonInstance
import com.nhaarman.mockitokotlin2.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.web3j.crypto.MnemonicUtils
import org.web3j.crypto.RawTransaction
import java.math.BigInteger
import java.util.*

class WalletStorageUnitTest {

    private lateinit var walletStorage: WalletStorage
    private val secureFileStorage: SecureFileStorage = mock()

    @Before
    fun setUp() {
        walletStorage = WalletStorageImpl(secureFileStorage)
    }

    @Test
    fun createKey() {
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            false
        )
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            false
        )
        doNothing().`when`(secureFileStorage).writeOnFilesDir(any(), any())

        walletStorage.createKey(name = "Hello").test()
            .assertComplete()
    }

    @Test
    fun createKeyExistingError() {
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
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

        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            false
        )
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
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

        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
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
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            true
        )

        walletStorage.isWalletCreated()
            .test()
            .assertComplete()
            .assertResult(true)
    }

    @Test
    fun getAccountDID() {
        val words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        val entropy = MnemonicUtils.generateEntropy(words)
        val seed = Seed(entropy, Date(), "Test")
        val seedString = newGsonInstance().toJson(seed)

        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            seedString.toByteArray()
        )

        walletStorage.getAccountDID()
            .test()
            .assertComplete()
            .assertResult("did:key:zQ3shju6YhWXKdxGskg7UeBN8vGs5QMmW7J7pxUzrAoEY3bLG")
    }

    @Test
    fun getAccountDIDSignature() {
        val words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        val entropy = MnemonicUtils.generateEntropy(words)
        val seed = Seed(entropy, Date(), "Test")
        val seedString = newGsonInstance().toJson(seed)

        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            seedString.toByteArray()
        )

        walletStorage.getAccountDIDSignature("hello")
            .test()
            .assertComplete()
            .assertResult("304402206f7914881a66a5692a2ebef505eb7d85ac377e6b57152bc5b908510191aaeead022072fb561b1e7324548df16f38c11326b951fa9f7f2f936caf6f7a2fc53a9aebcf")
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

//    @Test
//    fun getTezosWallet() {
//        val words = "victory fatigue diet funny senior coral motion canal leg elite hen model"
//        val entropy = MnemonicUtils.generateEntropy(words)
//        val seed = Seed(entropy, Date(), "Test")
//        val seedString = newGsonInstance().toJson(seed)
//
//        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
//            seedString.toByteArray()
//        )
//
//        walletStorage.getTezosWallet()
//            .test()
//            .assertValue {
//                it.mainAddress == "tz10000"
//            }
//    }

    @Test
    fun removeKeys() {
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            true
        )
        doNothing().`when`(secureFileStorage).writeOnFilesDir(any(), any())

        walletStorage.removeKeys()
            .test()
            .assertComplete()
    }

    @Test
    fun removeKeysError() {
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.SEED_FILE_NAME)).willReturn(
            false
        )
        given(secureFileStorage.isExistingOnFilesDir(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            false
        )

        walletStorage.removeKeys()
            .test()
            .assertError {
                it.message == "Wallet is not created!"
            }
    }
}