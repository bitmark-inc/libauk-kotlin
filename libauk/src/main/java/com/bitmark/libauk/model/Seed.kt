package com.bitmark.libauk.model

import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName
import java.util.*

class Seed(
    @Expose
    @SerializedName("data")
    val data: ByteArray,

    @Expose
    @SerializedName("creationDate")
    val creationDate: Date?,

    @Expose
    @SerializedName("name")
    var name: String
)