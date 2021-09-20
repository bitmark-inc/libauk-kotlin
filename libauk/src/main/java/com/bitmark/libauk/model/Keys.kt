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