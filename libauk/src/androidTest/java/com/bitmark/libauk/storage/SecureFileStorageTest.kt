package com.bitmark.libauk.storage

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.util.*

class SecureFileStorageTest {

    private val appContext = InstrumentationRegistry.getInstrumentation().targetContext

    private lateinit var filePrefix: String
    private val secureFileStorage = SecureFileStorageImpl(appContext, UUID.randomUUID())

    @Before
    fun beforeEach() {
        filePrefix = "${System.currentTimeMillis()}"
    }

    @After
    fun afterEach() {
        appContext.filesDir.listFiles()?.let { files -> files.forEach { it.deleteRecursively() } }
    }

    @Test
    fun testReadWriteStandardFileGateway() {
        val dataSet =
            mapOf(
                "$filePrefix-test.txt" to "test_content_1",
                "$filePrefix-test.key" to "",
                "$filePrefix-test" to "valvalvalvalvalvalvalvalvalvalvalval"
            )

        for (d in dataSet.entries) {
            secureFileStorage.rxCompletable { gw ->
                gw.writeOnFilesDir(
                    d.key,
                    d.value.toByteArray(),
                    true
                )
            }
                .test()
                .assertComplete()
                .assertNoErrors()

            secureFileStorage.readOnFilesDir(d.key).map { byteArray -> String(byteArray) }
                .test()
                .assertComplete()
                .assertNoErrors()
                .assertValue(d.value)
        }
    }

    @Test
    fun testReadWriteSecureFileGateway() {
        val dataSet =
            mapOf(
                "$filePrefix-test_secure.txt" to "test_content_1",
                "$filePrefix-test_secure.key" to "",
                "$filePrefix-test_secure" to "valvalvalvalvalvalvalvalvalvalvalval"
            )

        for (d in dataSet.entries) {
            secureFileStorage.rxCompletable { gw ->
                gw.writeOnFilesDir(
                    d.key,
                    d.value.toByteArray(),
                    true
                )
            }
                .test()
                .assertComplete()
                .assertNoErrors()

            secureFileStorage.readOnFilesDir(d.key).map { byteArray -> String(byteArray) }
                .test()
                .assertComplete()
                .assertNoErrors()
                .assertValue(d.value)
        }
    }

}