package com.bitmark.libauk

import android.content.Context
import com.bitmark.libauk.storage.SecureFileStorageImpl
import com.bitmark.libauk.storage.WalletStorage
import com.bitmark.libauk.storage.WalletStorageImpl
import org.web3j.crypto.Bip44WalletUtils
import java.util.UUID

class LibAuk {

    companion object {
        @Volatile
        private var INSTANCE: LibAuk? = null

        @Synchronized
        fun getInstance(): LibAuk =
            INSTANCE ?: LibAuk().also { INSTANCE = it }
    }

    fun getStorage(uuid: UUID, context: Context): WalletStorage {
        val storage = SecureFileStorageImpl(context, uuid)
        return WalletStorageImpl(storage)
    }

    fun calculateFirstEthAddress(words: String, passphrase: String): String {
        val credential = Bip44WalletUtils.loadBip44Credentials(passphrase, words)
        return credential.address
    }
}