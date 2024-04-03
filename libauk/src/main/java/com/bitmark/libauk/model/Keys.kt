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
data class SeedPublicData(
    val ethAddress: String,
    val creationDate: Date,
    val name: String?,
    val did: String,
    val preGenerateEthAddress: Map<Int, String>,
    val preGenerateTezosAddress: Map<Int, String>,
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
}