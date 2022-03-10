package com.bitmark.libauk

import android.content.Context
import com.bitmark.apiservice.configuration.GlobalConfiguration
import com.bitmark.apiservice.configuration.Network
import com.bitmark.libauk.storage.SecureFileStorageImpl
import com.bitmark.libauk.storage.WalletStorage
import com.bitmark.libauk.storage.WalletStorageImpl
import java.util.*

class LibAuk {

    companion object {
        @Volatile
        private var INSTANCE: LibAuk? = null

        @Synchronized
        fun getInstance(): LibAuk =
            INSTANCE ?: LibAuk().also { INSTANCE = it }
    }

    init {
        GlobalConfiguration.createInstance(
            GlobalConfiguration.builder()
                .withApiToken("bitmark")
                .withNetwork(Network.LIVE_NET)
        )
    }

    fun getStorage(uuid: UUID, context: Context): WalletStorage {
        val storage = SecureFileStorageImpl(context, uuid)
        return WalletStorageImpl(storage)
    }
}