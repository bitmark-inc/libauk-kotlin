import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

class BiometricUtil {
    companion object {
        fun withAuthenticate(
            activity: FragmentActivity,
            listener: BiometricPrompt.AuthenticationCallback
        ) {
            val executor = ContextCompat.getMainExecutor(activity)
            val biometricPrompt = BiometricPrompt(
                activity,
                executor,
                listener
            )

            val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate")
                .setSubtitle("Authenticate to access the data")
                .setNegativeButtonText("Cancel")

            val promptInfo = promptInfoBuilder.build()
            biometricPrompt.authenticate(promptInfo)

        }
    }
}