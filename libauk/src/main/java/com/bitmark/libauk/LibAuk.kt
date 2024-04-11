package com.bitmark.libauk

import android.content.Context
import com.bitmark.apiservice.configuration.GlobalConfiguration
import com.bitmark.apiservice.configuration.Network
import com.bitmark.libauk.storage.SecureFileStorageImpl
import com.bitmark.libauk.storage.WalletStorage
import com.bitmark.libauk.storage.WalletStorageImpl
import org.web3j.crypto.Bip44WalletUtils
import org.web3j.crypto.Keys
import org.web3j.crypto.MnemonicUtils
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

    fun calculateFirstEthAddress(words: String, passphrase: String): String {
        return try {
            val credential = Bip44WalletUtils.loadBip44Credentials(passphrase ?: "", words);
            credential.address
        } catch (e: Exception) {
            throw e
        }
    }
}