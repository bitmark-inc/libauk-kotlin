package com.bitmark.libauk.storage

import com.bitmark.libauk.model.KeyInfo
import com.bitmark.libauk.model.Seed
import com.bitmark.libauk.util.fromJson
import com.bitmark.libauk.util.newGsonInstance
import io.camlcase.kotlintezos.wallet.HDWallet
import io.reactivex.Completable
import io.reactivex.Single
import org.web3j.crypto.*
import java.security.SecureRandom
import java.util.*
import kotlin.Pair

interface WalletStorage {
    fun createKey(name: String): Completable
    fun importKey(words: List<String>, name: String, creationDate: Date?): Completable
    fun isWalletCreated(): Single<Boolean>
    fun getName(): Single<String>
    fun updateName(name: String): Completable
    fun getETHAddress(): Single<String>
    fun signPersonalMessage(message: ByteArray): Single<Sign.SignatureData>
    fun signTransaction(transaction: RawTransaction, chainId: Long): Single<ByteArray>
    fun exportMnemonicWords(): Single<String>
    fun getTezosWallet(): Single<HDWallet>
    fun removeKeys(): Completable
}

internal class WalletStorageImpl(private val secureFileStorage: SecureFileStorage) : WalletStorage {

    companion object {
        const val SEED_FILE_NAME = "libauk_seed.dat"
        const val ETH_KEY_INFO_FILE_NAME = "libauk_eth_key_info.dat"
    }

    override fun createKey(name: String): Completable = secureFileStorage.rxSingle { storage ->
        storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(ETH_KEY_INFO_FILE_NAME)
    }
        .map { isExisting ->
            if (!isExisting) {
                val mnemonic = generateMnemonic()
                val entropy = MnemonicUtils.generateEntropy(mnemonic)
                val seed = Seed(entropy, Date(), name)

                val credential =
                    WalletUtils.loadBip39Credentials("", mnemonic)
                val keyInfo = KeyInfo(credential.address, Date())
                Pair(seed, keyInfo)
            } else {
                throw Throwable("Wallet is already created!")
            }
        }
        .flatMapCompletable { (seed, keyInfo) ->
            secureFileStorage.rxCompletable { storage ->
                storage.writeOnFilesDir(
                    SEED_FILE_NAME,
                    newGsonInstance().toJson(seed).toByteArray()
                )
                storage.writeOnFilesDir(
                    ETH_KEY_INFO_FILE_NAME,
                    newGsonInstance().toJson(keyInfo).toByteArray()
                )
            }
        }

    override fun importKey(words: List<String>, name: String, creationDate: Date?): Completable =
        secureFileStorage.rxSingle { storage ->
            storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(ETH_KEY_INFO_FILE_NAME)
        }
            .map { isExisting ->
                if (!isExisting) {
                    val mnemonic = words.joinToString(separator = " ")
                    val entropy = MnemonicUtils.generateEntropy(mnemonic)
                    val seed = Seed(entropy, Date(), name)

                    val credential =
                        WalletUtils.loadBip39Credentials("", mnemonic)
                    val keyInfo = KeyInfo(credential.address, Date())
                    Pair(seed, keyInfo)
                } else {
                    throw Throwable("Wallet is already created!")
                }
            }
            .flatMapCompletable { (seed, keyInfo) ->
                secureFileStorage.rxCompletable { storage ->
                    storage.writeOnFilesDir(
                        SEED_FILE_NAME,
                        newGsonInstance().toJson(seed).toByteArray()
                    )
                    storage.writeOnFilesDir(
                        ETH_KEY_INFO_FILE_NAME,
                        newGsonInstance().toJson(keyInfo).toByteArray()
                    )
                }
            }

    override fun isWalletCreated(): Single<Boolean> = secureFileStorage.rxSingle { storage ->
        storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(ETH_KEY_INFO_FILE_NAME)
    }

    override fun getName(): Single<String> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(SEED_FILE_NAME)
        val seed = newGsonInstance().fromJson<Seed>(String(json))
        seed.name
    }

    override fun updateName(name: String): Completable =
        secureFileStorage.rxCompletable { storage ->
            val json = storage.readOnFilesDir(SEED_FILE_NAME)
            val seed = newGsonInstance().fromJson<Seed>(String(json))

            seed.name = name

            storage.writeOnFilesDir(
                SEED_FILE_NAME,
                newGsonInstance().toJson(seed).toByteArray()
            )
        }

    override fun getETHAddress(): Single<String> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(ETH_KEY_INFO_FILE_NAME)
        val keyInfo = newGsonInstance().fromJson<KeyInfo>(String(json))

        keyInfo.ethAddress
    }

    override fun signPersonalMessage(message: ByteArray): Single<Sign.SignatureData> =
        secureFileStorage.rxSingle { storage ->
            val json = storage.readOnFilesDir(SEED_FILE_NAME)
            val seed = newGsonInstance().fromJson<Seed>(String(json))
            val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
            val credential =
                WalletUtils.loadBip39Credentials("", mnemonic)

            Sign.signPrefixedMessage(message, credential.ecKeyPair)
        }

    override fun signTransaction(transaction: RawTransaction, chainId: Long): Single<ByteArray> =
        secureFileStorage.rxSingle { storage ->
            val json = storage.readOnFilesDir(SEED_FILE_NAME)
            val seed = newGsonInstance().fromJson<Seed>(String(json))
            val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
            val credential =
                WalletUtils.loadBip39Credentials("", mnemonic)
            TransactionEncoder.signMessage(transaction, chainId, credential)
        }

    override fun exportMnemonicWords(): Single<String> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(SEED_FILE_NAME)
        val seed = newGsonInstance().fromJson<Seed>(String(json))
        MnemonicUtils.generateMnemonic(seed.data)
    }

    override fun getTezosWallet(): Single<HDWallet> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(SEED_FILE_NAME)
        val seed = newGsonInstance().fromJson<Seed>(String(json))
        MnemonicUtils.generateMnemonic(seed.data)
    }.map {
        HDWallet(it.split(" "))
    }

    override fun removeKeys(): Completable = secureFileStorage.rxSingle { storage ->
        storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(ETH_KEY_INFO_FILE_NAME)
    }
        .map { isExisting ->
            if (isExisting) {
                true
            } else {
                throw Throwable("Wallet is not created!")
            }
        }
        .flatMapCompletable {
            secureFileStorage.rxCompletable { storage ->
                storage.deleteOnFilesDir(SEED_FILE_NAME)
                storage.deleteOnFilesDir(ETH_KEY_INFO_FILE_NAME)
            }
        }

    private fun generateMnemonic(): String {
        val initialEntropy = ByteArray(16)
        SecureRandom().nextBytes(initialEntropy)

        return MnemonicUtils.generateMnemonic(initialEntropy)
    }
}