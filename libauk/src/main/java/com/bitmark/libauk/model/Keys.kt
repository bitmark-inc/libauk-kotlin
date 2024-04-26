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
    @SerializedName("preGenerateEthAddresses")
    val preGenerateEthAddresses: Map<Int, String>,

    @Expose
    @SerializedName("preGenerateTezosAddresses")
    val preGenerateTezosAddresses: Map<Int, String>,

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
        if (preGenerateEthAddresses != other.preGenerateEthAddresses) return false
        if (preGenerateTezosAddresses != other.preGenerateTezosAddresses) return false
        if (!encryptionPrivateKey.contentEquals(other.encryptionPrivateKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ethAddress.hashCode()
        result = 31 * result + creationDate.hashCode()
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + did.hashCode()
        result = 31 * result + preGenerateEthAddresses.hashCode()
        result = 31 * result + preGenerateTezosAddresses.hashCode()
        result = 31 * result + encryptionPrivateKey.contentHashCode()
        return result
    }

    fun getAccountDIDPrivateKey(): Bip32ECKeyPair {
        return Bip32ECKeyPair.create(dIDPrivateKey, chainCode)
    }
}