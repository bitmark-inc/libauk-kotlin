package com.bitmark.libauk.storage

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import io.reactivex.Completable
import io.reactivex.Single
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.*
import android.os.Build
import android.util.Log

internal interface SecureFileStorage {

    fun writeOnFilesDir(name: String, data: ByteArray)

    fun readOnFilesDir(name: String): ByteArray

    fun isExistingOnFilesDir(name: String): Boolean

    fun deleteOnFilesDir(name: String): Boolean
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
        write(context.filesDir.absolutePath, getFileName(name), data)
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

    override fun readOnFilesDir(name: String): ByteArray =
        read(File(context.filesDir, getFileName(name)).absolutePath)

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
        val parameterSpec = KeyGenParameterSpec.Builder(
            MasterKey.DEFAULT_MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setKeySize(256)
            setDigests(KeyProperties.DIGEST_SHA512)
            setUserAuthenticationRequired(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setUnlockedDeviceRequired(true)
            }
            setRandomizedEncryptionRequired(true)
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        }.build()

        return MasterKey.Builder(context)
            .setKeyGenParameterSpec(parameterSpec)
            .build()
    }
}

internal fun <T> SecureFileStorage.rxSingle(action: (SecureFileStorage) -> T) =
    Single.fromCallable { action(this) }

internal fun SecureFileStorage.rxCompletable(action: (SecureFileStorage) -> Unit) =
    Completable.fromCallable { action(this) }
