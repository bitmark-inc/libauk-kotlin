package com.bitmark.libauk.util

import android.content.Context
import androidx.annotation.UiThread
import androidx.annotation.WorkerThread
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.bitmark.libauk.storage.SEED_FILE_NAME
import io.reactivex.Single
import io.reactivex.subjects.PublishSubject

class BiometricUtil {
    companion object {

        fun isAuthenReuired(fileNames: List<String>, context: Context): Boolean {
            return fileNames.any { it.contains(SEED_FILE_NAME) } && isDevicePasscodeEnabled(context)
        }

        private fun isDevicePasscodeEnabled(context: Context): Boolean {
            val sharedPreferences = context.getSharedPreferences(
                "FlutterSharedPreferences",
                Context.MODE_PRIVATE
            )

            return sharedPreferences.getBoolean("flutter.device_passcode", false)
        }

        @UiThread
        fun <T : Any> withAuthenticate(
            activity: FragmentActivity,
            onAuthenticationSucceeded: (BiometricPrompt.AuthenticationResult) -> T,
            onAuthenticationFailed: () -> T,
            onAuthenticationError: (Int, CharSequence) -> T
        ): Single<T> {
            val subject = PublishSubject.create<T>()
            val executor = ContextCompat.getMainExecutor(activity)
            val biometricPrompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try{
                            val data = onAuthenticationSucceeded(result)
                            subject.onNext(data)
                        } catch (e: Exception) {
                            subject.onError(e)
                        }
                    }

                    override fun onAuthenticationFailed() {
                        Single.fromCallable { onAuthenticationFailed() }.subscribe(
                        ).let {  }
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {
                        try{
                            val data = onAuthenticationError(errorCode, errString)
                            subject.onNext(data)
                        } catch (e: Exception) {
                            subject.onError(e)
                        }
                    }
                }
            )

            val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate")
                .setSubtitle("Authenticate to access the data")
                .setNegativeButtonText("Cancel")

            val promptInfo = promptInfoBuilder.build()
            biometricPrompt.authenticate(promptInfo)

            return subject.firstOrError()
        }
    }
}