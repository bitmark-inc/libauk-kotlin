import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName

@JsonSerialize
class AddressIndex (
  @Expose
  @SerializedName("chain")
  val chain: String,

  @Expose
  @SerializedName("index")
  val index: Int
) {}