package com.bitmark.libauk.model

import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName
import java.util.*

@JsonSerialize
data class KeyIdentity(
    @Expose
    @SerializedName("words")
    val words: String,

    @Expose
    @SerializedName("passphrase")
    val passphrase: String
)

@JsonSerialize
data class KeyInfo(
    @Expose
    @SerializedName("ethAddress")
    val ethAddress: String,

    @Expose
    @SerializedName("creationDate")
    val creationDate: Date
)
@JsonSerialize
data class SeedPublicData(
    @Expose
    @SerializedName("ethAddress")
    val ethAddress: String,

    @Expose
    @SerializedName("creationDate")
    val creationDate: Date,

    @Expose
    @SerializedName("name")
    val name: String?,

    @Expose
    @SerializedName("did")
    val did: String,

    @Expose
    @SerializedName("preGenerateEthAddress")
    val preGenerateEthAddress: Map<Int, String>,

    @Expose
    @SerializedName("preGenerateTezosAddress")
    val preGenerateTezosAddress: Map<Int, String>,

    @Expose
    @SerializedName("encryptionPrivateKey")
    val encryptionPrivateKey: ByteArray,
//    val tezosPublicKeys: Map<Int, String>,

//    var _encryptionPrivateKeyBase64: String? = null,
//    var _accountDIDPrivateKeyBase64: String? = null
) {
    //    var encryptionPrivateKey: Secp256k1.Signing.PrivateKey?
//        get() {
//            return try {
//                _encryptionPrivateKeyBase64?.let { base64String ->
//                    val data = android.util.Base64.decode(base64String, android.util.Base64.DEFAULT)
//                    Secp256k1.Signing.PrivateKey(rawRepresentation = data)
//                }
//            } catch (e: Exception) {
//                throw RuntimeException("Failed to initialize private key: ${e.message}")
//            }
//        }
//        set(value) {
//            _encryptionPrivateKeyBase64 = value?.let {
//                android.util.Base64.encodeToString(it.rawRepresentation, android.util.Base64.DEFAULT)
//            }
//        }
//
//    var accountDIDPrivateKey: Secp256k1.Signing.PrivateKey?
//        get() {
//            return try {
//                _accountDIDPrivateKeyBase64?.let { base64String ->
//                    val data = android.util.Base64.decode(base64String, android.util.Base64.DEFAULT)
//                    Secp256k1.Signing.PrivateKey(rawRepresentation = data)
//                }
//            } catch (e: Exception) {
//                throw RuntimeException("Failed to initialize private key: ${e.message}")
//            }
//        }
//        set(value) {
//            _accountDIDPrivateKeyBase64 = value?.let {
//                android.util.Base64.encodeToString(it.rawRepresentation, android.util.Base64.DEFAULT)
//            }
//        }
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SeedPublicData

        if (ethAddress != other.ethAddress) return false
        if (creationDate != other.creationDate) return false
        if (name != other.name) return false
        if (did != other.did) return false
        if (preGenerateEthAddress != other.preGenerateEthAddress) return false
        if (preGenerateTezosAddress != other.preGenerateTezosAddress) return false
        if (!encryptionPrivateKey.contentEquals(other.encryptionPrivateKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ethAddress.hashCode()
        result = 31 * result + creationDate.hashCode()
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + did.hashCode()
        result = 31 * result + preGenerateEthAddress.hashCode()
        result = 31 * result + preGenerateTezosAddress.hashCode()
        result = 31 * result + encryptionPrivateKey.contentHashCode()
        return result
    }
}