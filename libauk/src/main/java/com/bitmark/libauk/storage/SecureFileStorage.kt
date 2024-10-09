package com.bitmark.libauk.storage

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import io.reactivex.Completable
import io.reactivex.Single
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.*
import android.util.Log
import java.security.KeyStore

internal interface SecureFileStorage {

    fun writeOnFilesDir(name: String, data: ByteArray)

    fun readOnFilesDir(name: String): ByteArray

    fun isExistingOnFilesDir(name: String): Boolean

    fun deleteOnFilesDir(name: String): Boolean

    fun cleanKeyStoreAlias()
}

internal class SecureFileStorageImpl(
    private val context: Context,
    private val alias: UUID
) : SecureFileStorage {
    private fun getFileName(name: String) = "$alias-${name}-default_alias"

    private fun write(path: String, name: String, data: ByteArray) {
        val file = getEncryptedFile("$path/$name", false)
        file.openFileOutput().apply {
            write(data)
            flush()
            close()
        }
    }

    override fun writeOnFilesDir(name: String, data: ByteArray) {
        try {
            write(context.filesDir.absolutePath, getFileName(name), data)
        } catch (e: Exception) {
            Log.e("writeOnFilesDir", "error: $e")
            cleanKeyStoreAlias()
            write(context.filesDir.absolutePath, getFileName(name), data)
        }
    }

    private fun read(path: String): ByteArray {
        val file = getEncryptedFile(path, true)
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

    override fun readOnFilesDir(name: String): ByteArray = try {
        read(File(context.filesDir, getFileName(name)).absolutePath)
    } catch (e: Exception) {
        Log.e("readOnFilesDir", "error: $e")
        cleanKeyStoreAlias()
        read(File(context.filesDir, getFileName(name)).absolutePath)
    }

    private fun isExisting(path: String): Boolean = File(path).exists()

    override fun isExistingOnFilesDir(name: String): Boolean =
        isExisting(File(context.filesDir, getFileName(name)).absolutePath)

    private fun delete(path: String): Boolean = File(path).let { file ->
        Log.d("delete path", "path to delete: $path")
        if (!file.exists()) true
        else if (file.isDirectory) {
            file.deleteRecursively()
        } else {
            file.delete()
        }
    }

    override fun deleteOnFilesDir(name: String): Boolean =
        delete(File(context.filesDir, getFileName(name)).absolutePath)

    override fun cleanKeyStoreAlias() {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        val alias = keyStore.aliases().toList();
        alias.forEach {
            Log.d("alias", "alias: $it")
            keyStore.deleteEntry(it)
        }
    }

    private fun getEncryptedFile(path: String, read: Boolean) = File(path).let { f ->
        if (f.isDirectory) throw IllegalArgumentException("do not support directory")
        if (read && !f.exists() && !f.createNewFile()) {
            throw IllegalStateException("cannot create new file for reading")
        } else if (!read && f.exists() && !f.delete()) {
            throw IllegalStateException("cannot delete file before writing")
        }
        getEncryptedFileBuilder(f).build()
    }

    private fun getEncryptedFileBuilder(f: File) = EncryptedFile.Builder(
        context,
        f,
        getMasterKey(),
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
    )

    private fun getMasterKey(): MasterKey {
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        return MasterKey.Builder(context, DEFAULT_MASTER_KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setUserAuthenticationRequired(false)
            .build()
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val DEFAULT_MASTER_KEY_ALIAS = "_default_master_key_alias_"
    }
}

internal fun <T> SecureFileStorage.rxSingle(action: (SecureFileStorage) -> T) =
    Single.fromCallable { action(this) }

internal fun SecureFileStorage.rxCompletable(action: (SecureFileStorage) -> Unit) =
    Completable.fromCallable { action(this) }
