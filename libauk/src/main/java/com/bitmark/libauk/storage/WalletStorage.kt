package com.bitmark.libauk.storage

import com.bitmark.libauk.model.KeyIdentity
import com.bitmark.libauk.model.KeyInfo
import com.bitmark.libauk.util.fromJson
import com.bitmark.libauk.util.newGsonInstance
import io.reactivex.Completable
import io.reactivex.Single
import org.web3j.crypto.*
import java.security.SecureRandom
import java.util.*
import kotlin.Pair

interface WalletStorage {
    fun createKey(): Completable
    fun isWalletCreated(): Single<Boolean>
    fun getETHAddress(): Single<String>
    fun signPersonalMessage(message: ByteArray): Single<Sign.SignatureData>
    fun signTransaction(transaction: RawTransaction, chainId: Long): Single<ByteArray>
    fun exportSeed(): Single<KeyIdentity>
}

internal class WalletStorageImpl(private val secureFileStorage: SecureFileStorage) : WalletStorage {

    companion object {
        const val KEY_IDENTITY_FILE_NAME = "libauk_key_identity.dat"
        const val ETH_KEY_INFO_FILE_NAME = "libauk_eth_key_info.dat"
    }

    override fun createKey(): Completable = secureFileStorage.rxSingle { storage ->
        storage.isExisting(KEY_IDENTITY_FILE_NAME) && storage.isExisting(ETH_KEY_INFO_FILE_NAME)
    }
        .map { isExisting ->
            if (isExisting) {
                val mnemonic = generateMnemonic()
                val keyIdentity = KeyIdentity(mnemonic, "")

                val credential =
                    WalletUtils.loadBip39Credentials(keyIdentity.passphrase, keyIdentity.words)
                val keyInfo = KeyInfo(credential.address, Date())
                Pair(keyIdentity, keyInfo)
            } else {
                throw Throwable("Wallet is already created!")
            }
        }
        .flatMapCompletable { (keyIdentity, keyInfo) ->
            secureFileStorage.rxCompletable { storage ->
                storage.writeOnFilesDir(
                    KEY_IDENTITY_FILE_NAME,
                    newGsonInstance().toJson(keyIdentity).toByteArray()
                )
                storage.writeOnFilesDir(
                    ETH_KEY_INFO_FILE_NAME,
                    newGsonInstance().toJson(keyInfo).toByteArray()
                )
            }
        }

    override fun isWalletCreated(): Single<Boolean> = secureFileStorage.rxSingle { storage ->
        storage.isExisting(KEY_IDENTITY_FILE_NAME) && storage.isExisting(ETH_KEY_INFO_FILE_NAME)
    }

    override fun getETHAddress(): Single<String> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(ETH_KEY_INFO_FILE_NAME)
        val keyInfo = newGsonInstance().fromJson<KeyInfo>(String(json))

        keyInfo.ethAddress
    }

    override fun signPersonalMessage(message: ByteArray): Single<Sign.SignatureData> =
        secureFileStorage.rxSingle { storage ->
            val json = storage.readOnFilesDir(KEY_IDENTITY_FILE_NAME)
            val keyIdentity = newGsonInstance().fromJson<KeyIdentity>(String(json))

            val credential =
                WalletUtils.loadBip39Credentials(keyIdentity.passphrase, keyIdentity.words)

            Sign.signPrefixedMessage(message, credential.ecKeyPair)
        }

    override fun signTransaction(transaction: RawTransaction, chainId: Long): Single<ByteArray> =
        secureFileStorage.rxSingle { storage ->
            val json = storage.readOnFilesDir(KEY_IDENTITY_FILE_NAME)
            val keyIdentity = newGsonInstance().fromJson<KeyIdentity>(String(json))

            val credential =
                WalletUtils.loadBip39Credentials(keyIdentity.passphrase, keyIdentity.words)
            TransactionEncoder.signMessage(transaction, chainId, credential)
        }

    override fun exportSeed(): Single<KeyIdentity> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(KEY_IDENTITY_FILE_NAME)
        newGsonInstance().fromJson<KeyIdentity>(String(json))
    }

    private fun generateMnemonic(): String {
        val initialEntropy = ByteArray(16)
        SecureRandom().nextBytes(initialEntropy)

        return MnemonicUtils.generateMnemonic(initialEntropy)
    }
}