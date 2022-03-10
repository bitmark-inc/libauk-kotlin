package com.bitmark.libauk.storage

import com.bitmark.apiservice.configuration.GlobalConfiguration
import com.bitmark.apiservice.configuration.Network
import com.bitmark.apiservice.utils.Address
import com.bitmark.apiservice.utils.ArrayUtil
import com.bitmark.cryptography.crypto.Ed25519
import com.bitmark.cryptography.crypto.Sha3256
import com.bitmark.cryptography.crypto.encoder.Base58
import com.bitmark.cryptography.crypto.key.PublicKey
import com.bitmark.libauk.Const.BITMARK_DERIVATION_PATH
import com.bitmark.libauk.model.KeyInfo
import com.bitmark.libauk.model.Seed
import com.bitmark.libauk.util.fromJson
import com.bitmark.libauk.util.newGsonInstance
import io.camlcase.kotlintezos.wallet.HDWallet
import io.reactivex.Completable
import io.reactivex.Single
import org.web3j.crypto.*
import wallet.core.jni.CoinType
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
    fun getBitmarkAddress(): Single<String>
    fun removeKeys(): Completable
}

internal class WalletStorageImpl(private val secureFileStorage: SecureFileStorage) : WalletStorage {

    companion object {
        const val SEED_FILE_NAME = "libauk_seed.dat"
        const val ETH_KEY_INFO_FILE_NAME = "libauk_eth_key_info.dat"
    }

    override fun createKey(name: String): Completable = secureFileStorage.rxSingle { storage ->
        storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(
            ETH_KEY_INFO_FILE_NAME
        )
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
            storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(
                ETH_KEY_INFO_FILE_NAME
            )
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
        storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(
            ETH_KEY_INFO_FILE_NAME
        )
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

    override fun getBitmarkAddress(): Single<String> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(SEED_FILE_NAME)
        val seed = newGsonInstance().fromJson<Seed>(String(json))
        MnemonicUtils.generateMnemonic(seed.data)
    }.map {
        val wallet = wallet.core.jni.HDWallet(it, "")
        val seed = wallet.getKey(CoinType.BITCOIN, BITMARK_DERIVATION_PATH).data()
        val keyPair = Ed25519.generateKeyPairFromSeed(seed)

        generateAccountNumber(keyPair.publicKey())
    }

    override fun removeKeys(): Completable = secureFileStorage.rxSingle { storage ->
        storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(
            ETH_KEY_INFO_FILE_NAME
        )
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

    private fun generateAccountNumber(key: PublicKey): String? {
        GlobalConfiguration.createInstance(
            GlobalConfiguration.builder()
                .withApiToken("bitmark")
                .withNetwork(Network.LIVE_NET)
        )
        val address = Address.getDefault(key, GlobalConfiguration.network())
        val keyVariantVarInt = address.prefix
        val publicKeyBytes = key.toBytes()
        val preChecksum = ArrayUtil.concat(keyVariantVarInt, publicKeyBytes)
        val checksum = ArrayUtil.slice(
            Sha3256.hash(preChecksum),
            0,
            Address.CHECKSUM_LENGTH
        )
        return Base58.BASE_58.encode(
            ArrayUtil.concat(
                keyVariantVarInt,
                publicKeyBytes,
                checksum
            )
        )
    }
}