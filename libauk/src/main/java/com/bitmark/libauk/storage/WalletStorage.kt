package com.bitmark.libauk.storage

import at.favre.lib.hkdf.HKDF
import com.bitmark.libauk.Const.ACCOUNT_DERIVATION_PATH
import com.bitmark.libauk.Const.ENCRYPT_KEY_DERIVATION_PATH
import com.bitmark.libauk.model.KeyInfo
import com.bitmark.libauk.model.Seed
import com.bitmark.libauk.util.fromJson
import com.bitmark.libauk.util.newGsonInstance
import io.camlcase.kotlintezos.model.TezosError
import io.camlcase.kotlintezos.model.TezosErrorType
import io.camlcase.kotlintezos.wallet.HDWallet
import io.camlcase.kotlintezos.wallet.crypto.SodiumFacade
import io.camlcase.kotlintezos.wallet.crypto.hexStringToByteArray
import io.camlcase.kotlintezos.wallet.crypto.toHexString
import io.camlcase.kotlintezos.wallet.crypto.watermarkAndHash
import io.reactivex.Completable
import io.reactivex.Single
import org.bouncycastle.crypto.digests.SHA256Digest
import org.web3j.crypto.*
import org.web3j.utils.Numeric
import wallet.core.jni.Base58
import wallet.core.jni.Curve
import wallet.core.jni.PrivateKey
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.Pair

interface WalletStorage {
    fun createKey(passphrase: String? = "", name: String): Completable
    fun importKey(
        words: List<String>,
        passphrase: String? = "",
        name: String,
        creationDate: Date?
    ): Completable

    fun isWalletCreated(): Single<Boolean>
    fun getName(): Single<String>
    fun updateName(name: String): Completable
    fun getAccountDID(): Single<String>
    fun getAccountDIDSignature(message: String): Single<String>
    fun getETHAddress(): Single<String>
    fun ethSignMessage(message: ByteArray, needToHash: Boolean): Single<Sign.SignatureData>
    fun ethSignTransaction(transaction: RawTransaction, chainId: Long): Single<ByteArray>
    fun getETHAddressWithIndex(index: Int): Single<String>
    fun ethSignMessageWithIndex(
        message: ByteArray,
        needToHash: Boolean,
        index: Int
    ): Single<Sign.SignatureData>

    fun ethSignTransactionWithIndex(
        transaction: RawTransaction,
        chainId: Long,
        index: Int
    ): Single<ByteArray>

    fun encryptFile(input: File, output: File): Completable
    fun decryptFile(input: File, output: File, usingLegacy: Boolean): Completable
    fun exportMnemonicPassphrase(): Single<String>
    fun exportMnemonicWords(): Single<String>
    fun getTezosPublicKey(): Single<String>
    fun tezosSignMessage(message: ByteArray): Single<ByteArray>
    fun tezosTransaction(forgedHex: String): Single<ByteArray>
    fun getTezosPublicKeyWithIndex(index: Int): Single<String>
    fun tezosSignMessageWithIndex(message: ByteArray, index: Int): Single<ByteArray>
    fun tezosTransactionWithIndex(forgedHex: String, index: Int): Single<ByteArray>
    fun removeKeys(): Completable
}

internal class WalletStorageImpl(private val secureFileStorage: SecureFileStorage) : WalletStorage {

    companion object {
        const val SEED_FILE_NAME = "libauk_seed.dat"
        const val ETH_KEY_INFO_FILE_NAME = "libauk_eth_key_info.dat"
    }

    override fun createKey(passphrase: String?, name: String): Completable =
        secureFileStorage.rxSingle { storage ->
            storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(
                ETH_KEY_INFO_FILE_NAME
            )
        }
            .map { isExisting ->
                if (!isExisting) {
                    val mnemonic = generateMnemonic()
                    val entropy = MnemonicUtils.generateEntropy(mnemonic)
                    val seed = Seed(entropy, Date(), name, passphrase ?: "")

                    val credential =
                        Bip44WalletUtils.loadBip44Credentials(passphrase ?: "", mnemonic)

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

    override fun importKey(
        words: List<String>,
        passphrase: String?,
        name: String,
        creationDate: Date?
    ): Completable =
        secureFileStorage.rxSingle { storage ->
            storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(
                ETH_KEY_INFO_FILE_NAME
            )
        }
            .map { isExisting ->
                if (!isExisting) {
                    val mnemonic = words.joinToString(separator = " ")
                    val entropy = MnemonicUtils.generateEntropy(mnemonic)
                    val seed = Seed(entropy, Date(), name, passphrase ?: "")

                    val credential =
                        Bip44WalletUtils.loadBip44Credentials(passphrase ?: "", mnemonic)
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

    override fun getAccountDID(): Single<String> = secureFileStorage.rxSingle { storage ->
        val seed = getWalletSeed(storage);
        val masterKeypair = Bip32ECKeyPair.generateKeyPair(seed)
        val bip44Keypair = Bip32ECKeyPair.deriveKeyPair(masterKeypair, ACCOUNT_DERIVATION_PATH)

        val prefix: ByteArray = listOf(231, 1).map { it.toByte() }.toByteArray()
        val compressedPubKey = compressPubKey(bip44Keypair.publicKey)
        "did:key:z${Base58.encode(prefix + compressedPubKey.hexStringToByteArray())}"
    }

    override fun getAccountDIDSignature(message: String): Single<String> =
        secureFileStorage.rxSingle { storage ->
            val seed = getWalletSeed(storage);
            val masterKeypair = Bip32ECKeyPair.generateKeyPair(seed)
            val bip44Keypair = Bip32ECKeyPair.deriveKeyPair(masterKeypair, ACCOUNT_DERIVATION_PATH)

            val sigData = Sign.signMessage(
                SHA256Digest(message.toByteArray(Charsets.UTF_8)).encodedState,
                bip44Keypair,
                false
            )

            derSignature(sigData)
        }

    override fun getETHAddress(): Single<String> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(ETH_KEY_INFO_FILE_NAME)
        val keyInfo = newGsonInstance().fromJson<KeyInfo>(String(json))
        keyInfo.ethAddress
    }

    override fun getETHAddressWithIndex(index: Int): Single<String> =
        secureFileStorage.rxSingle { storage ->
            val credential = createETHCredentialWithIndex(storage, index)
            credential.address
        }

    override fun ethSignMessage(
        message: ByteArray,
        needToHash: Boolean
    ): Single<Sign.SignatureData> =
        secureFileStorage.rxSingle { storage ->
            val json = storage.readOnFilesDir(SEED_FILE_NAME)
            val seed = newGsonInstance().fromJson<Seed>(String(json))
            val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
            val credential =
                Bip44WalletUtils.loadBip44Credentials(seed.passphrase ?: "", mnemonic)

            Sign.signMessage(message, credential.ecKeyPair, needToHash)
        }

    override fun ethSignMessageWithIndex(
        message: ByteArray,
        needToHash: Boolean,
        index: Int
    ): Single<Sign.SignatureData> =
        secureFileStorage.rxSingle { storage ->
            val credential = createETHCredentialWithIndex(storage, index)
            Sign.signMessage(message, credential.ecKeyPair, needToHash)
        }

    override fun ethSignTransaction(transaction: RawTransaction, chainId: Long): Single<ByteArray> =
        secureFileStorage.rxSingle { storage ->
            val json = storage.readOnFilesDir(SEED_FILE_NAME)
            val seed = newGsonInstance().fromJson<Seed>(String(json))
            val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
            val credential =
                Bip44WalletUtils.loadBip44Credentials(seed.passphrase ?: "", mnemonic)
            TransactionEncoder.signMessage(transaction, chainId, credential)
        }

    override fun ethSignTransactionWithIndex(
        transaction: RawTransaction,
        chainId: Long,
        index: Int
    ): Single<ByteArray> =
        secureFileStorage.rxSingle { storage ->
            val credential = createETHCredentialWithIndex(storage, index)
            TransactionEncoder.signMessage(transaction, chainId, credential)
        }

    private fun getEncryptKey(usingLegacy: Boolean = false): Single<ByteArray> {
        return secureFileStorage.rxSingle { storage ->
            val seed = getWalletSeed(storage)
            val masterKeypair = Bip32ECKeyPair.generateKeyPair(seed)
            val bip44Keypair =
                Bip32ECKeyPair.deriveKeyPair(masterKeypair, ENCRYPT_KEY_DERIVATION_PATH)
            val bytes = Numeric.toBytesPadded(bip44Keypair.privateKey, 32)

            if (usingLegacy) {
                bytes
            } else {
                HKDF.fromHmacSha256().extractAndExpand(ByteArray(0), bytes, null, 32)
            }
        }
    }

    private fun getWalletSeed(storage: SecureFileStorage): ByteArray {
        val json = storage.readOnFilesDir(SEED_FILE_NAME)
        val seed = newGsonInstance().fromJson<Seed>(String(json))
        val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
        return MnemonicUtils.generateSeed(mnemonic, seed.passphrase ?: "")
    }

    private fun getNonce(): ByteArray {
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        return nonce
    }

    override fun encryptFile(input: File, output: File): Completable {
        return getEncryptKey().map { encryptKey ->
            val key = SecretKeySpec(encryptKey, "ChaCha20")
            val nonce = getNonce()
            val iv = IvParameterSpec(nonce)
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.ENCRYPT_MODE, key, iv)
            val encrypted = cipher.doFinal(input.readBytes())
            ByteBuffer.allocate(encrypted.size + nonce.size)
                .put(nonce)
                .put(encrypted)
                .array()
        }.flatMapCompletable { encrypted ->
            output.writeBytes(encrypted)
            Completable.complete()
        }
    }

    override fun decryptFile(input: File, output: File, usingLegacy: Boolean): Completable {
        return getEncryptKey(usingLegacy).map { encryptKey ->
            val data = input.readBytes()
            val buffer = ByteBuffer.wrap(data)
            val cipherText = ByteArray(data.size - 12)
            val nonce = ByteArray(12)
            buffer.get(nonce)
            buffer.get(cipherText)
            val iv = IvParameterSpec(nonce)
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            val key = SecretKeySpec(encryptKey, "ChaCha20")
            cipher.init(Cipher.DECRYPT_MODE, key, iv)
            cipher.doFinal(cipherText)
        }.flatMapCompletable { decrypted ->
            output.writeBytes(decrypted)
            Completable.complete()
        }
    }

    override fun exportMnemonicPassphrase(): Single<String> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(SEED_FILE_NAME)
        val seed = newGsonInstance().fromJson<Seed>(String(json))
        seed.passphrase ?: ""
    }

    override fun exportMnemonicWords(): Single<String> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(SEED_FILE_NAME)
        val seed = newGsonInstance().fromJson<Seed>(String(json))
        MnemonicUtils.generateMnemonic(seed.data)
    }

    private fun getTezosWallet(): Single<HDWallet> = secureFileStorage.rxSingle { storage ->
        val json = storage.readOnFilesDir(SEED_FILE_NAME)
        val seed = newGsonInstance().fromJson<Seed>(String(json))
        val mnemonic = MnemonicUtils.generateMnemonic(seed.data);
        Pair(mnemonic, seed.passphrase)
    }.map { (mnemonic, passphrase) ->
        HDWallet(mnemonic.split(" "), passphrase = passphrase);
    }

    private fun getTezosWalletWithIndex(index: Int): Single<HDWallet> =
        secureFileStorage.rxSingle { storage ->
            val json = storage.readOnFilesDir(SEED_FILE_NAME)
            val seed = newGsonInstance().fromJson<Seed>(String(json))
            val mnemonic = MnemonicUtils.generateMnemonic(seed.data);
            Pair(mnemonic, seed.passphrase)
        }.map { (mnemonic, passphrase) ->
            val path = "m/44\'/1729\'/${index}\'/0\'"
            HDWallet(mnemonic.split(" "), derivationPath = path, passphrase = passphrase);
        }

    override fun getTezosPublicKey(): Single<String> = getTezosWallet().map {
        it.publicKey.base58Representation
    }

    override fun getTezosPublicKeyWithIndex(index: Int): Single<String> =
        getTezosWalletWithIndex(index).map {
            it.publicKey.base58Representation
        }

    override fun tezosSignMessage(message: ByteArray): Single<ByteArray> = getTezosWallet().map {
        val hashedMessage = SodiumFacade.hash(message, 32)
        PrivateKey(it.secretKey.encoded).sign(hashedMessage, Curve.ED25519)
    }

    override fun tezosSignMessageWithIndex(message: ByteArray, index: Int): Single<ByteArray> =
        getTezosWalletWithIndex(index).map {
            val hashedMessage = SodiumFacade.hash(message, 32)
            PrivateKey(it.secretKey.encoded).sign(hashedMessage, Curve.ED25519)
        }

    override fun tezosTransaction(forgedHex: String): Single<ByteArray> = getTezosWallet().map {
        it.sign(forgedHex)
    }

    override fun tezosTransactionWithIndex(forgedHex: String, index: Int): Single<ByteArray> =
        getTezosWalletWithIndex(index).map {
            val bytesToSign = forgedHex.hexStringToByteArray().watermarkAndHash()
                ?: throw TezosError(
                    TezosErrorType.SIGNING_ERROR,
                    exception = IllegalArgumentException("The given hexadecimal string could not be watermarked and hashed.")
                )
            PrivateKey(it.secretKey.encoded).sign(bytesToSign, Curve.ED25519)
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

    private fun compressPubKey(pubKey: BigInteger): String {
        val pubKeyYPrefix = if (pubKey.testBit(0)) "03" else "02"
        val pubKeyHex: String = Numeric.toBytesPadded(pubKey, 64).toHexString()
        val pubKeyX = pubKeyHex.substring(0, 64)
        return pubKeyYPrefix + pubKeyX
    }

    private fun derSignature(sigData: Sign.SignatureData): String {
        var rp = listOf(0).map { it.toByte() }.toByteArray() + sigData.r
        var sp = listOf(0).map { it.toByte() }.toByteArray() + sigData.s

        while (rp.size > 1 && rp[0].toInt() == 0 && rp[1].toInt() >= 0) {
            rp = rp.drop(1).toByteArray()
        }

        while (sp.size > 1 && sp[0].toInt() == 0 && sp[1].toInt() >= 0) {
            sp = sp.drop(1).toByteArray()
        }

        val derBytes = listOf(0x30, 4 + rp.size + sp.size, 0x02, rp.size).map { it.toByte() }
            .toByteArray() + rp + listOf(0x02, sp.size).map { it.toByte() }.toByteArray() + sp
        return derBytes.toHexString()
    }

    private fun createETHCredentialWithIndex(storage: SecureFileStorage, index: Int): Credentials {
        val seed = getWalletSeed(storage)
        val masterKeypair = Bip32ECKeyPair.generateKeyPair(seed)
        val path = intArrayOf(
            44 or Bip32ECKeyPair.HARDENED_BIT,
            60 or Bip32ECKeyPair.HARDENED_BIT,
            0 or Bip32ECKeyPair.HARDENED_BIT,
            0,
            index
        )
        val bip44Keypair = Bip32ECKeyPair.deriveKeyPair(masterKeypair, path)
        return Credentials.create(bip44Keypair)
    }
}