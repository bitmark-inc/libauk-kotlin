import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import com.bitmark.libauk.LibAuk
import com.bitmark.libauk.storage.SecureFileStorageImpl
import com.bitmark.libauk.util.BiometricUtil
import io.reactivex.Single
import java.io.File
import java.util.UUID

class SecurityFileUtil {
    fun readAllFiles(context: Context, nameFilterFunc: (String) -> Boolean): Single<Map<String, ByteArray>> {
        val map = mutableMapOf<String, ByteArray>()
        val listFileName = context.filesDir.list()
        val isAuthenRequired = BiometricUtil.isAuthenReuired(listFileName.toList(), context)
        // readFunc is a function that reads the file return ByteArray
        val readFunc: (File) -> ByteArray? = { file ->
            if (nameFilterFunc(file.name)) {
                val uuid = file.name.substringBefore("-")
                SecureFileStorageImpl(
                    context,
                    UUID.fromString(uuid)
                ).readOnFilesDirWithoutAuthentication(file.name)
            }
            else{
                null
            }
        }
        if (isAuthenRequired) {
            BiometricUtil.withAuthenticate(
                activity = context as FragmentActivity,
                onAuthenticationSucceeded = { result ->
                    context.filesDir.listFiles()?.forEach { file ->
                        readFunc(file)?.also { map[file.name] = it }
                    }
                    map
                },
                onAuthenticationError = { _, _ -> map },
                onAuthenticationFailed = { map }
            )
        }
        return Single.fromCallable {
            context.filesDir.listFiles()?.forEach { file ->
                readFunc(file)?.also { map[file.name] = it }
            }
            map
        }
    }
}