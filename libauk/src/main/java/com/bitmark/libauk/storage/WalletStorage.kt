package com.bitmark.libauk.storage

import androidx.lifecycle.Transformations.map
import at.favre.lib.hkdf.HKDF
import com.bitmark.apiservice.configuration.GlobalConfiguration
import com.bitmark.apiservice.utils.Address
import com.bitmark.apiservice.utils.ArrayUtil
import com.bitmark.cryptography.crypto.Sha256
import com.bitmark.cryptography.crypto.Sha3256
import com.bitmark.cryptography.crypto.encoder.Base58
import com.bitmark.cryptography.crypto.key.PublicKey
import com.bitmark.libauk.Const.ACCOUNT_DERIVATION_PATH
import com.bitmark.libauk.Const.ENCRYPT_KEY_DERIVATION_PATH
import com.bitmark.libauk.model.KeyInfo
import com.bitmark.libauk.model.Seed
import com.bitmark.libauk.model.SeedPublicData
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
import org.web3j.crypto.*
import org.web3j.utils.Numeric
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

const val SEED_FILE_NAME = "libauk_seed.dat"
const val ETH_KEY_INFO_FILE_NAME = "libauk_eth_key_info.dat"
const val SEED_PUBLIC_DATA_FILE_NAME = "libauk_seed_public_data.dat"
const val PRE_GENERATE_ADDRESS_LIMIT = 10
interface WalletStorage {
    fun createKey(passphrase: String? = "", name: String, isPrivate: Boolean): Completable
    fun importKey(
        words: List<String>,
        passphrase: String? = "",
        name: String,
        creationDate: Date?,
        isPrivate: Boolean
    ): Completable

    fun exportSeed(withAuthentication: Boolean): Single<Seed>

    fun generateSeedPublicData(seed: Seed) : SeedPublicData

    fun isWalletCreated(): Single<Boolean>
    fun getName(): Single<String>
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

    fun readOnFilesDir(name: String): Single<ByteArray>
    fun writeOnFilesDir(name: String, data: ByteArray, isPrivate: Boolean)
    fun encryptFile(input: File, output: File): Completable
    fun decryptFile(input: File, output: File, usingLegacy: Boolean): Completable
    fun exportMnemonicPassphrase(): Single<String>
    fun exportMnemonicWords(): Single<String>
    fun tezosSignMessage(message: ByteArray): Single<ByteArray>
    fun tezosTransaction(forgedHex: String): Single<ByteArray>
    fun getTezosPublicKeyWithIndex(index: Int): Single<String>
    fun tezosSignMessageWithIndex(message: ByteArray, index: Int): Single<ByteArray>
    fun tezosTransactionWithIndex(forgedHex: String, index: Int): Single<ByteArray>
    fun removeKeys(): Completable

    fun removeKey(name: String): Completable
}

internal class WalletStorageImpl(private val secureFileStorage: SecureFileStorage) : WalletStorage {

    override fun createKey(passphrase: String?, name: String, isPrivate: Boolean): Completable = secureFileStorage.rxSingle { storage ->
        storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(
            SEED_PUBLIC_DATA_FILE_NAME
        )
    }
        .map { isExisting ->
            if (!isExisting) {
                val mnemonic = generateMnemonic()
                val entropy = MnemonicUtils.generateEntropy(mnemonic)
                val seed = Seed(entropy, Date(), name, passphrase ?: "")
                val seedPublicData = generateSeedPublicData(seed)
                Pair(seed, seedPublicData)
            } else {
                throw Throwable("Wallet is already created!")
            }
        }
        .flatMapCompletable { (seed, seedPublicData) ->
            secureFileStorage.rxCompletable { storage ->
                storage.writeOnFilesDir(
                    SEED_FILE_NAME,
                    newGsonInstance().toJson(seed).toByteArray(),
                    isPrivate
                )
                storage.writeOnFilesDir(
                    SEED_PUBLIC_DATA_FILE_NAME,
                    newGsonInstance().toJson(seedPublicData).toByteArray(),
                    false
                )
            }
        }

    override fun importKey(words: List<String>, passphrase: String?, name: String, creationDate: Date?, isPrivate: Boolean): Completable =
        isWalletCreated()
            .map { isExisting ->
                if (!isExisting) {
                    val mnemonic = words.joinToString(separator = " ")
                    val entropy = MnemonicUtils.generateEntropy(mnemonic)
                    val seed = Seed(entropy, Date(), name, passphrase ?: "")
                    val seedPublicData = generateSeedPublicData(seed)
                    Pair(seed, seedPublicData)
                } else {
                    throw Throwable("Wallet is already created!")
                }
            }
            .flatMapCompletable { (seed, seedPublicData) ->
                secureFileStorage.rxCompletable { storage ->
                    storage.writeOnFilesDir(
                        SEED_FILE_NAME,
                        newGsonInstance().toJson(seed).toByteArray(),
                        isPrivate
                    )
                    storage.writeOnFilesDir(
                        SEED_PUBLIC_DATA_FILE_NAME,
                        newGsonInstance().toJson(seedPublicData).toByteArray(),
                        false
                    )
                }
            }

    override fun exportSeed(withAuthentication: Boolean): Single<Seed> = if (withAuthentication) {
        getSeed()
    } else {
        getSeedWithoutAuthentication()
    }

    override fun isWalletCreated(): Single<Boolean> = secureFileStorage.rxSingle { storage ->
        storage.isExistingOnFilesDir(SEED_FILE_NAME) && storage.isExistingOnFilesDir(
            SEED_PUBLIC_DATA_FILE_NAME
        )
    }

    override fun generateSeedPublicData(seed: Seed) : SeedPublicData {
        /* ethAddress */
        val ethAddress = generateETHAddress(seed)

        /* seed name */
        val seedName = seed.name

        /* accountDidKey */
        val accountDID = generateAccountDID(seed)

        val seedByte = getSeedBytes(seed)
        val accountDidPrivateKey = Bip32ECKeyPair.generateKeyPair(seedByte)

        /* pre-generate 100 eth addresses */
        val preGenerateEthAddresses = preGenerateETHAddresses(seed, 0, PRE_GENERATE_ADDRESS_LIMIT)

        val preGenerateTezosAddresses = preGenerateTezosAddresses(seed, 0, PRE_GENERATE_ADDRESS_LIMIT)

        /* encrytion private key */
        val encryptionPrivateKey = generateEncryptKey(seed)

        /* tezos public keys */
        val preGenerateTezosPublicKeys = generateTezosPublicKeys(seed, 0, PRE_GENERATE_ADDRESS_LIMIT)

        return SeedPublicData(
            ethAddress,
            Date(),
            seedName,
            accountDID,
            preGenerateEthAddresses,
            preGenerateTezosAddresses,
            preGenerateTezosPublicKeys,
            encryptionPrivateKey,
            accountDidPrivateKey.privateKey,
            accountDidPrivateKey.chainCode
        )
    }

    private fun getSeedPublicData(): Single<SeedPublicData> =
        secureFileStorage.readOnFilesDir(SEED_PUBLIC_DATA_FILE_NAME).map { json ->
            try{
            val seedPublicData = newGsonInstance().fromJson<SeedPublicData>(String(json))
            seedPublicData
            } catch (e: Exception) {
                throw Throwable("Failed to get seedPublicData")
        }
    }

    private fun getSeed(): Single<Seed> = secureFileStorage.readOnFilesDir(SEED_FILE_NAME).map { json ->
        newGsonInstance().fromJson<Seed>(String(json))
    }

    private fun getSeedBytes(walletSeed: Seed): ByteArray {
        val mnemonic = MnemonicUtils.generateMnemonic(walletSeed.data)
        val seed = MnemonicUtils.generateSeed(mnemonic, walletSeed.passphrase ?: "")
        return seed
    }

    private fun getSeedWithoutAuthentication(): Single<Seed> = Single.fromCallable(
        {secureFileStorage.readOnFilesDirWithoutAuthentication(SEED_FILE_NAME)}
    ).map { json ->
        newGsonInstance().fromJson<Seed>(String(json))
    }

    override fun getName(): Single<String> = getSeedPublicData()
        .map { seedPublicData ->
            // Process seedPublicData and extract the name
            seedPublicData.name ?: ""
        }
        .onErrorResumeNext { error ->
            Single.fromCallable { ""  }
        }

    private fun generateAccountDID(walletSeed: Seed) : String {
        val seed = getSeedBytes(walletSeed)
        val masterKeypair = Bip32ECKeyPair.generateKeyPair(seed)
        val bip44Keypair = Bip32ECKeyPair.deriveKeyPair(masterKeypair, ACCOUNT_DERIVATION_PATH)
        val prefix: ByteArray = listOf(231, 1).map { it.toByte() }.toByteArray()
        val compressedPubKey = compressPubKey(bip44Keypair.publicKey)
        return "did:key:z${Base58.BASE_58.encode(prefix + compressedPubKey.hexStringToByteArray())}"
    }

    override fun getAccountDID(): Single<String> = getSeedPublicData()
        .map { seedPublicData ->
            // Process seedPublicData and extract the accountDID
            seedPublicData.did
        }
        .onErrorResumeNext {
            getSeed().map { seed ->
                generateAccountDID(seed)
            }
        }

    override fun getAccountDIDSignature(message: String): Single<String> {
        return getSeedPublicData().map { seedPublicData ->
            try {
                seedPublicData.getAccountDIDPrivateKey()
            } catch (e: Exception) {
                throw Throwable("Failed to get accountDIDPrivateKey")
            }
        }.onErrorResumeNext { error ->
            getSeed().map { seed ->
                val seedByte = getSeedBytes(seed)
                Bip32ECKeyPair.generateKeyPair(seedByte)
            }}
            .map { masterKeypair ->
                val bip44Keypair = Bip32ECKeyPair.deriveKeyPair(masterKeypair, ACCOUNT_DERIVATION_PATH)

                val sigData = Sign.signMessage(
                    Sha256.hash(message.toByteArray(Charsets.UTF_8)),
                    bip44Keypair,
                    false
                )
                derSignature(sigData)
            }
    }

    private fun generateETHAddress(seed: Seed): String
    {
        val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
        val credential = Bip44WalletUtils.loadBip44Credentials(seed.passphrase ?: "", mnemonic)
        return credential.address
    }

     override fun getETHAddress(): Single<String> = getSeedPublicData()
        .map { seedPublicData ->
            // Process seedPublicData and extract the ethAddress
            seedPublicData.ethAddress
        }
        .onErrorResumeNext { error ->
            getSeed().map { seed ->
                generateETHAddress(seed)
            }
        }

    private fun preGenerateETHAddresses(seed: Seed, start: Int, end: Int): Map<Int, String>
    {
        val addresses = mutableMapOf<Int, String>()
        for (i in start until end) {
            val credential = generateETHCredentialWithIndex(seed, i)
            addresses[i] = credential.address
        }
        return addresses
    }

    private fun preGenerateTezosAddresses(seed: Seed, start: Int, end: Int): Map<Int, String>
    {
        val addresses = mutableMapOf<Int, String>()
        for (i in start until end) {
            val wallet = getTezosWalletWithIndexFromSeed(seed, i)
            addresses[i] = wallet.publicKey.base58Representation
        }
        return addresses
    }

    override fun getETHAddressWithIndex(index: Int): Single<String> =
        getSeedPublicData()
            .map { seedPublicData ->
                // Process seedPublicData and extract the ethAddress with index
                val address = seedPublicData.preGenerateEthAddresses[index]
                if (address.isNullOrEmpty()) {
                    throw Throwable("Failed to get ethAddress with index: $index")
                } else {
                    address
                }
            }.onErrorResumeNext { _ ->
                createETHCredentialWithIndex(index).map { credential ->
                    credential.address
                }
            }

    override fun ethSignMessage(
        message: ByteArray,
        needToHash: Boolean
    ): Single<Sign.SignatureData> {
        return getSeed().map { seed ->
            val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
            val credential =
                Bip44WalletUtils.loadBip44Credentials(seed.passphrase ?: "", mnemonic)

            Sign.signMessage(message, credential.ecKeyPair, needToHash)
        }
    }

    override fun ethSignMessageWithIndex(
        message: ByteArray,
        needToHash: Boolean,
        index: Int
    ): Single<Sign.SignatureData> =
        createETHCredentialWithIndex(index).map { credential ->
            Sign.signMessage(message, credential.ecKeyPair, needToHash)
        }

    override fun ethSignTransaction(transaction: RawTransaction, chainId: Long): Single<ByteArray> {
        return getSeed().map { seed ->
            val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
            val credential =
                Bip44WalletUtils.loadBip44Credentials(seed.passphrase ?: "", mnemonic)
            TransactionEncoder.signMessage(transaction, chainId, credential)
        }
    }

    override fun ethSignTransactionWithIndex(
        transaction: RawTransaction,
        chainId: Long,
        index: Int
    ): Single<ByteArray> =
        createETHCredentialWithIndex(index).map { credential ->
            TransactionEncoder.signMessage(transaction, chainId, credential)
        }

    override fun readOnFilesDir(name: String): Single<ByteArray> {
        return secureFileStorage.readOnFilesDir(name)
    }

    override fun writeOnFilesDir(name: String, data: ByteArray, isPrivate: Boolean){
        secureFileStorage.writeOnFilesDir(name, data, isPrivate)
    }

    private fun generateEncryptKey(walletSeed: Seed): ByteArray {
        val seedB = getSeedBytes(walletSeed)
        val masterKeypair = Bip32ECKeyPair.generateKeyPair(seedB)
        val bip44Keypair = Bip32ECKeyPair.deriveKeyPair(masterKeypair, ENCRYPT_KEY_DERIVATION_PATH)
        return Numeric.toBytesPadded(bip44Keypair.privateKey, 32)
    }
    private fun getEncryptKey(usingLegacy: Boolean = false): Single<ByteArray> {
        return getSeedPublicData().map { seedPublicData ->
            seedPublicData.encryptionPrivateKey
        }.onErrorResumeNext { error ->
            getSeed().map { seed ->
                generateEncryptKey(seed)
            }
        }
            .map {
            if (usingLegacy) {
                it
            } else {
                HKDF.fromHmacSha256().extractAndExpand(ByteArray(0), it, null, 32)
            }
        }
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
    override fun exportMnemonicPassphrase(): Single<String> = getSeed().map { seed ->
        seed.passphrase ?: ""
    }

    override fun exportMnemonicWords(): Single<String> {
        return getSeed().map { seed ->
            MnemonicUtils.generateMnemonic(seed.data)
        }
    }

    private fun exportMnemonicWordsToBackup(): Single<String> {
        return getSeedWithoutAuthentication().map { seed ->
            MnemonicUtils.generateMnemonic(seed.data)
        }
    }

    private fun getTezosWallet(): Single<HDWallet> {
        return getSeed().map { seed ->
            val mnemonic = MnemonicUtils.generateMnemonic(seed.data);
            Pair(mnemonic, seed.passphrase)
        }.map { (mnemonic, passphrase) ->
            HDWallet(mnemonic.split(" "), passphrase = passphrase);
        }
    }

    private fun getTezosWalletWithIndex(index: Int): Single<HDWallet> {
        return getSeed().map { seed ->
            getTezosWalletWithIndexFromSeed(seed, index)
        }
    }

    private fun getTezosWalletWithIndexFromSeed(seed: Seed, index: Int): HDWallet {
        val mnemonic = MnemonicUtils.generateMnemonic(seed.data)
        val path = "m/44\'/1729\'/${index}\'/0\'"
        return HDWallet(mnemonic.split(" "), derivationPath = path, passphrase = seed.passphrase)
    }

    private fun generateTezosPublicKeys(walletSeed: Seed, start: Int, end: Int): Map<Int, String> {
        val publicKeys = mutableMapOf<Int, String>()
        for (i in start until end) {
            val path = "m/44\'/1729\'/${i}\'/0\'"
            val wallet = HDWallet(MnemonicUtils.generateMnemonic(walletSeed.data).split(" "), derivationPath = path, passphrase = walletSeed.passphrase)
            publicKeys[i] = wallet.publicKey.base58Representation
        }
        return publicKeys
    }

    override fun getTezosPublicKeyWithIndex(index: Int): Single<String> =
        getSeedPublicData().map {
            val address = it.preGenerateTezosPublicKeys[index]
            if (address.isNullOrEmpty()) {
                throw Throwable("Failed to get tezosPublicKey with index: $index")
            } else {
                address
            }
        }.onErrorResumeNext(
            getSeed().map { seed ->
                val wallet = getTezosWalletWithIndexFromSeed(seed, index)
                val publicKey = wallet.publicKey.base58Representation
                publicKey
            }
        )

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

    override fun removeKeys(): Completable = isWalletCreated()
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
                storage.deleteOnFilesDir(SEED_PUBLIC_DATA_FILE_NAME)
            }
        }

    override fun removeKey(name: String): Completable = secureFileStorage.rxCompletable { storage ->
        storage.deleteOnFilesDir(name)
    }

    private fun generateMnemonic(): String {
        val initialEntropy = ByteArray(16)
        SecureRandom().nextBytes(initialEntropy)

        return MnemonicUtils.generateMnemonic(initialEntropy)
    }

    private fun generateAccountNumber(key: PublicKey): String? {
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

    private fun generateETHCredentialWithIndex(seed: Seed, index: Int): Credentials {
        val seedB = getSeedBytes(seed)
        val masterKeypair = Bip32ECKeyPair.generateKeyPair(seedB)
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

    private fun createETHCredentialWithIndex(index: Int): Single<Credentials> {
        return getSeed().map {seed ->
            generateETHCredentialWithIndex(seed, index)
        }
    }
}