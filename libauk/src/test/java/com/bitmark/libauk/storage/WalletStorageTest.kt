package com.bitmark.libauk.storage

import com.bitmark.libauk.model.KeyIdentity
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.doNothing
import com.nhaarman.mockitokotlin2.given
import com.nhaarman.mockitokotlin2.mock
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.web3j.crypto.RawTransaction
import java.math.BigInteger

class WalletStorageTest {

    private lateinit var walletStorage: WalletStorage
    private val secureFileStorage: SecureFileStorage = mock()

    @Before
    fun setUp() {
        walletStorage = WalletStorageImpl(secureFileStorage)
    }

    @Test
    fun createKey() {
        given(secureFileStorage.isExisting(WalletStorageImpl.KEY_IDENTITY_FILE_NAME)).willReturn(
            true
        )
        given(secureFileStorage.isExisting(WalletStorageImpl.ETH_KEY_INFO_FILE_NAME)).willReturn(
            true
        )
        doNothing().`when`(secureFileStorage).writeOnFilesDir(any(), any())

        walletStorage.createKey().test()
            .assertComplete()
    }

    @Test
    fun isWalletCreated() {
        given(secureFileStorage.isExisting(WalletStorageImpl.KEY_IDENTITY_FILE_NAME)).willReturn(
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
        val identity =
            "{\"words\":\"victory fatigue diet funny senior coral motion canal leg elite hen model\",\"passphrase\":\"\"}"
        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.KEY_IDENTITY_FILE_NAME)).willReturn(
            identity.toByteArray()
        )

        walletStorage.signPersonalMessage("hello".toByteArray())
            .test()
            .assertComplete()
    }

    @Test
    fun signTransaction() {
        val identity =
            "{\"words\":\"victory fatigue diet funny senior coral motion canal leg elite hen model\",\"passphrase\":\"\"}"
        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.KEY_IDENTITY_FILE_NAME)).willReturn(
            identity.toByteArray()
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
        val identity =
            "{\"words\":\"victory fatigue diet funny senior coral motion canal leg elite hen model\",\"passphrase\":\"\"}"
        given(secureFileStorage.readOnFilesDir(WalletStorageImpl.KEY_IDENTITY_FILE_NAME)).willReturn(
            identity.toByteArray()
        )

        walletStorage.exportSeed()
            .test()
            .assertResult(
                KeyIdentity(
                    "victory fatigue diet funny senior coral motion canal leg elite hen model",
                    ""
                )
            )
    }
}