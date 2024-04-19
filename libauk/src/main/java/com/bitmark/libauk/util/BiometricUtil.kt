import android.content.Context
import androidx.annotation.UiThread
import androidx.annotation.WorkerThread
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.reactivex.Completable
import io.reactivex.Single
import io.reactivex.subjects.PublishSubject
import org.web3j.abi.datatypes.Bool

class BiometricUtil {
    companion object {
        @UiThread
        fun <T> withAuthenticate(
            activity: FragmentActivity,
            @WorkerThread onAuthenticationSucceeded: (BiometricPrompt.AuthenticationResult) -> T,
            @WorkerThread onAuthenticationFailed: () -> T,
            @WorkerThread onAuthenticationError: (Int, CharSequence) -> T
        ): Single<T> {
            val subject = PublishSubject.create<T>()
            val executor = ContextCompat.getMainExecutor(activity)
            val biometricPrompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        Single.fromCallable { onAuthenticationSucceeded(result) }.map {
                            subject.onNext(it)
                        }
                    }

                    override fun onAuthenticationFailed() {
                        Single.fromCallable { onAuthenticationFailed() }.map {
                            subject.onNext(it)
                        }
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {
                        Single.fromCallable { onAuthenticationError(errorCode, errString) }
                            .map {
                                subject.onNext(it)
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