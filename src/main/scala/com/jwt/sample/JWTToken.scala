package com.jwt.sample

import io.igl.jwt._

import scala.util.Try

trait JWT {

  /**
    *
    * @return the key / secret to use for signing and validating the signature
    */
  protected def secret: String

  /**
    *
    * @return the issuer of the token
    */
  protected def issuer: String

  /**
    *
    * @param subject the subject to be used
    * @param audience the target audience for the token
    * @param claims the claims to be included in the token
    * @param expiryDate the expiry date for the token
    * @return a string representing the jwt token
    */
  def generateToken(subject: String, audience: String, claims: Seq[ClaimValue], expiryDate: Long): String = {
    val headers = Seq(Alg(Algorithm.HS256), Typ("JWT"))
    val payload = Seq(Iss(issuer), Aud(audience), Sub(subject), Exp(expiryDate)) ++ claims
    val jwtToken = new DecodedJwt(headers, payload)
    jwtToken.encodedAndSigned(secret)
  }

  /**
    *
    * @param audience the target audience of the token
    * @param requiredClaims the required claims present in the token
    * @param token the jwt token
    * @return returns a (Subject, Jwt) tuple wrapped in Success when successful, otherwise Failure
    */
  def validateToken[T <: ClaimField](audience: String, requiredClaims: Set[T], token: String): Try[Jwt] = {
    DecodedJwt.validateEncodedJwt(
      token,
      secret,
      Algorithm.HS256,
      Set(Typ),
      Set(Iss, Aud, Sub, Exp) ++ requiredClaims,
      iss = Option(Iss(issuer)),
      aud = Option(Aud(audience))
    )
  }
}
