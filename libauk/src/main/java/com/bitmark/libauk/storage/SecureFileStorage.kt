package com.bitmark.libauk.storage

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import io.reactivex.Completable
import io.reactivex.Single
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.KeyStore
import java.util.UUID

internal interface SecureFileStorage {

    fun writeOnFilesDir(name: String, data: ByteArray, isPrivate: Boolean)

    fun readOnFilesDir(name: String, isPrivate: Boolean): ByteArray

    fun isExistingOnFilesDir(name: String): Boolean

    fun deleteOnFilesDir(name: String): Boolean
}

@Suppress("DEPRECATION")
internal class SecureFileStorageImpl constructor(private val context: Context, private val alias: UUID) : SecureFileStorage {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
    private val sharedPreferences = context.getSharedPreferences("beaconsdk", Context.MODE_PRIVATE)

    private var masterKeyAlias: String?
        get() = sharedPreferences.getString(KEY_MASTER_KEY_ALIAS, null)
        set(value) {
            value?.let { sharedPreferences.edit().putString(KEY_MASTER_KEY_ALIAS, it).apply() }
        }

    private fun write(path: String, name: String, data: ByteArray, isPrivate: Boolean) {
        val file = getEncryptedFile("$path/$name", false, isPrivate)
        file.openFileOutput().apply {
            write(data)
            flush()
            close()
        }
    }

    override fun writeOnFilesDir(name: String, data: ByteArray, isPrivate: Boolean) {
        write(context.filesDir.absolutePath, "$alias-$name", data, isPrivate)
    }

    private fun read(path: String, isPrivate: Boolean): ByteArray {
        val file = getEncryptedFile(path, true, isPrivate)
        if (File(path).length() == 0L) return byteArrayOf()
        val inputStream = file.openFileInput()
        val os = ByteArrayOutputStream()
        var nextByte: Int = inputStream.read()
        while (nextByte != -1) {
            os.write(nextByte)
            nextByte = inputStream.read()
        }
        return os.toByteArray()
    }

    override fun readOnFilesDir(name: String, isPrivate: Boolean): ByteArray =
        read(File(context.filesDir, "$alias-$name").absolutePath, isPrivate)

    private fun isExisting(path: String): Boolean = File(path).exists()

    override fun isExistingOnFilesDir(name: String): Boolean =
        isExisting(File(context.filesDir, "$alias-$name").absolutePath)

    private fun delete(path: String): Boolean = File(path).let { file ->
        if (!file.exists()) true
        else if (file.isDirectory) {
            file.deleteRecursively()
        } else {
            file.delete()
        }
    }

    override fun deleteOnFilesDir(name: String): Boolean =
        delete(File(context.filesDir, "$alias-$name").absolutePath)

    private fun getEncryptedFile(path: String, read: Boolean, isPrivate: Boolean) = File(path).let { f ->
        if (f.isDirectory) throw IllegalArgumentException("do not support directory")
        if (read && !f.exists() && !f.createNewFile()) {
            throw IllegalStateException("cannot create new file for reading")
        } else if (!read && f.exists() && !f.delete()) {
            throw IllegalStateException("cannot delete file before writing")
        }
        getEncryptedFileBuilder(f, isPrivate).build()
    }

    private fun getEncryptedFileBuilder(f: File, isPrivate: Boolean) = EncryptedFile.Builder(
        context,
        f,
        getMasterKey(isPrivate),
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
    )

    private fun getMasterKey(isPrivate: Boolean): MasterKey {
        keyStore.load(null)
        val keyAlias = masterKeyAlias ?: UUID.randomUUID().toString().also { masterKeyAlias = it }
        val authenticationTimeoutInSeconds = 30
        val parameterSpecBuilder = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).apply {
            setKeySize(256)
            setDigests(KeyProperties.DIGEST_SHA512)
            setUserAuthenticationRequired(isPrivate)
            setRandomizedEncryptionRequired(true)
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            parameterSpecBuilder.setUserAuthenticationParameters(authenticationTimeoutInSeconds, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        else {
            //This method was deprecated in API level 30.
            parameterSpecBuilder.setUserAuthenticationValidityDurationSeconds(authenticationTimeoutInSeconds)
        }


        val  parameterSpec = parameterSpecBuilder.build()

        return MasterKey.Builder(context, keyAlias)
            .setKeyGenParameterSpec(parameterSpec)
            .build()
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val KEY_MASTER_KEY_ALIAS = "masterKeyAlias"
    }
}

internal fun <T> SecureFileStorage.rxSingle(action: (SecureFileStorage) -> T) =
    Single.fromCallable { action(this) }

internal fun SecureFileStorage.rxCompletable(action: (SecureFileStorage) -> Unit) =
    Completable.fromCallable { action(this) }
