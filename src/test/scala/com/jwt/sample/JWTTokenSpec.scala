package com.jwt.sample

import io.igl.jwt.{ClaimField, ClaimValue, Jwt, Sub}
import org.scalatest.{FlatSpec, Matchers}
import org.scalatest.concurrent.ScalaFutures
import play.api.libs.json.{JsString, JsValue}

import scala.concurrent.duration._
import scala.util.{Failure, Success}

object jwtTokenGen extends JWT {
  override protected def secret: String = "my-signature-key"

  override protected def issuer: String = "jwt-token-sample-app"

  def validateAndDecryptToken[T <: ClaimField](audience: String, requiredClaims: Set[T], token: String): Jwt = {
    validateToken(audience, requiredClaims, token) match {
      case Success(res) => res
      case Failure(e) => throw new SecurityException(s"Unauthorized Access", e)
    }
  }
}

case class CV(value: String) extends ClaimValue {
  override val field: ClaimField = CV
  override val jsValue: JsValue = JsString(value)
}

object CV extends ClaimField {
  override def attemptApply(value: JsValue): Option[ClaimValue] = value.asOpt[String].map(apply)
  override val name: String = "cv"
}

class JWTSpec extends FlatSpec with Matchers with ScalaFutures {
  private val expiryDuration = 30.seconds.toMillis
  private val audience = "auth-rest-api"
  private val subject = "subject"

  "The JWT Token Generator" should "create a valid token" in {
    val jwtToken = jwtTokenGen.generateToken(subject, audience, Seq(CV("private claim")), (System.currentTimeMillis + expiryDuration) / 1000)
    val jwt = jwtTokenGen.validateAndDecryptToken(audience, Set(CV), jwtToken)

    assert(jwt.getClaim[Sub].map(_.value).getOrElse("") == subject)
    assert(jwt.getClaim[CV].get.value == "private claim")
  }


  "The JWT Token Generator" should "decrypt a valid token" in {
    val jwtToken = jwtTokenGen.generateToken(subject, audience, Seq(CV("private claim")), (System.currentTimeMillis + expiryDuration) / 1000)
    val jwt = jwtTokenGen.validateAndDecryptToken(audience, Set(CV), jwtToken)

    assert(jwt.getClaim[Sub].map(_.value).getOrElse("") == subject)
    assert(jwt.getClaim[CV].get.value == "private claim")
  }

  "The JWT Token Generator" should "fail if token is tampered" in {
    val expiryDate = (System.currentTimeMillis + expiryDuration * 1000) / 1000
    val jwtToken = jwtTokenGen.generateToken(subject, audience, Seq(CV("private claim")), expiryDate)
    val token2 = jwtTokenGen.generateToken(subject, audience, Seq(CV("private claim2")), expiryDate)
    val jwtTokenParts = jwtToken.split("\\.")
    val token2Parts = token2.split("\\.")
    val newToken = s"""${jwtTokenParts(0)}.${token2Parts(1)}.${jwtTokenParts(2)}"""

    val ex = intercept[SecurityException] {
      jwtTokenGen.validateAndDecryptToken(audience, Set(CV), newToken)
      fail()
    }

    assert(ex.getCause.getMessage == "Signature is incorrect")
  }

  "The JWT Token Generator" should "fail if the token is expired" in {
    val jwtToken = jwtTokenGen.generateToken(subject, audience, Seq(CV("private claim")), System.currentTimeMillis / 1000)
    val ex = intercept[SecurityException] {
      jwtTokenGen.validateAndDecryptToken(audience, Set(CV), jwtToken)
      fail()
    }

    assert(ex.getCause.getMessage == "Jwt has expired")
  }
}