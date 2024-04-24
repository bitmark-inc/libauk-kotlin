package com.bitmark.libauk.model

import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName
import org.web3j.crypto.Bip32ECKeyPair
import java.math.BigInteger
import java.util.*

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
    @SerializedName("preGenerateTezosPublicKeys")
    val preGenerateTezosPublicKeys: Map<Int, String>,

    @Expose
    @SerializedName("encryptionPrivateKey")
    val encryptionPrivateKey: ByteArray,

    @Expose
    @SerializedName("dIDPrivateKey")
    private  var dIDPrivateKey: BigInteger,

    @Expose
    @SerializedName("chainCode")
    private val chainCode: ByteArray

) {
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

    fun getAccountDIDPrivateKey(): Bip32ECKeyPair {
        return Bip32ECKeyPair.create(dIDPrivateKey, chainCode)
    }
}