package com.bitmark.libauk

import android.content.Context
import com.bitmark.libauk.storage.SecureFileStorageImpl
import com.bitmark.libauk.storage.WalletStorage
import com.bitmark.libauk.storage.WalletStorageImpl

class LibAuk constructor(context: Context) {

    val wallet: WalletStorage

    init {
        val storage = SecureFileStorageImpl(context)
        wallet = WalletStorageImpl(storage)
    }

    companion object {
        @Volatile
        private var INSTANCE: LibAuk? = null

        @Synchronized
        fun getInstance(context: Context): LibAuk =
            INSTANCE ?: LibAuk(context).also { INSTANCE = it }
    }
}