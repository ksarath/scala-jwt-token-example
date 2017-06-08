# JWT Token Sample in Scala

Using [iain-logan jwt library](https://github.com/iain-logan/jwt).

## Usage

Creating a JWT token generator
------------------------------
```scala
object jwtTokenGen extends JWT {
    override protected def secret: String = "my-signature-key"
    override protected def issuer: String = "jwt-token-sample-app"
}
```
Creating private headers and claims
-----------------------------------
```scala
case class PrivateClaim(value: String) extends ClaimValue {
  override val field: ClaimField = PrivateClaim
  override val jsValue: JsValue = JsString(value)
}

object PrivateClaim extends ClaimField {
  override def attemptApply(value: JsValue): Option[ClaimValue] = value.asOpt[String].map(apply)
  override val name: String = "claim_field_name"
}
```
Generating a JWT token
----------------------
```scala
val jwtToken = jwtTokenGen.generateToken("token_subject", "target_audience", Seq(PrivateClaim("private claim")), (System.currentTimeMillis + 30000) / 1000)
```
Validating and decrypting JWT token
-----------------------------------
```scala
jwtTokenGen.validateAndDecryptToken("target_audience", Set(PrivateClaim), jwtToken)
```
Returns a `Jwt` wrapped in `Success` on success, otherwise `Failure`.

# License

This software is licensed under the MIT license, see [LICENSE](https://github.com/iain-logan/jwt/blob/master/LICENSE).
