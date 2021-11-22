package com.bitmark.libauk.storage

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import io.reactivex.Completable
import io.reactivex.Single
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.*

internal interface SecureFileStorage {
    fun write(path: String, name: String, data: ByteArray)

    fun writeOnFilesDir(name: String, data: ByteArray)

    fun read(path: String): ByteArray

    fun readOnFilesDir(name: String): ByteArray

    fun isExisting(path: String): Boolean

    fun isExistingOnFilesDir(name: String): Boolean

    fun delete(path: String): Boolean

    fun deleteOnFilesDir(name: String): Boolean
}

internal class SecureFileStorageImpl constructor(private val context: Context, private val alias: UUID) : SecureFileStorage {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    override fun write(path: String, name: String, data: ByteArray) {
        val file = getEncryptedFile("$path/$name", false)
        file.openFileOutput().apply {
            write(data)
            flush()
            close()
        }
    }

    override fun writeOnFilesDir(name: String, data: ByteArray) {
        write(context.filesDir.absolutePath, name, data)
    }

    override fun read(path: String): ByteArray {
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

    override fun readOnFilesDir(name: String): ByteArray =
        read(File(context.filesDir, name).absolutePath)

    override fun isExisting(path: String): Boolean = File(path).exists()

    override fun isExistingOnFilesDir(name: String): Boolean =
        isExisting(File(context.filesDir, name).absolutePath)

    override fun delete(path: String): Boolean = File(path).let { file ->
        if (!file.exists()) true
        else if (file.isDirectory) {
            file.deleteRecursively()
        } else {
            file.delete()
        }
    }

    override fun deleteOnFilesDir(name: String): Boolean =
        delete(File(context.filesDir, name).absolutePath)

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
        masterKey,
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
    ).setKeysetAlias(alias.toString())
}

internal fun <T> SecureFileStorage.rxSingle(action: (SecureFileStorage) -> T) =
    Single.fromCallable { action(this) }

internal fun SecureFileStorage.rxCompletable(action: (SecureFileStorage) -> Unit) =
    Completable.fromCallable { action(this) }
