import android.content.Context
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
        fun withAuthenticate(
            activity: FragmentActivity,
            listener: BiometricPrompt.AuthenticationCallback
        ): Single<Bool> {
            val subject = PublishSubject.create<Bool>()
            val executor = ContextCompat.getMainExecutor(activity)
            val biometricPrompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        Single.fromCallable { listener.onAuthenticationSucceeded(result) }.map {
                            subject.onNext(Bool(true))
                        }
                    }

                    override fun onAuthenticationFailed() {
                        Single.fromCallable { listener.onAuthenticationFailed() }.map {
                            subject.onNext(Bool(false))
                        }
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {
                        Single.fromCallable { listener.onAuthenticationError(errorCode, errString) }
                            .map {
                                subject.onNext(Bool(false))
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