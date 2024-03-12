package utils

import (
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	uuid "github.com/satori/go.uuid"
	"time"
)

type TokenDetails struct {
	Token     *string
	TokenUuid string
	UserID    string
	ExpiresIn *int64
}

// uses RSA encryption for creating token
// public key(authenticate) and private key(access and refresh token) concept
func CreateToken(userid string, ttl time.Duration, privateKey string) (*TokenDetails, error) {
	now := time.Now().UTC()
	td := &TokenDetails{
		ExpiresIn: new(int64),  //memory allocated using new()
		Token:     new(string), //memory allocated for the Token value
	}
	*td.ExpiresIn = now.Add(ttl).Unix()  //adding the additional time coming from ttl which is ACCESS_TOKEN_EXPIRED_IN=15m
	td.TokenUuid = uuid.NewV4().String() //UUID is set
	td.UserID = userid
	//base64 encoded string gets converted to normal string so that signing of jwt can take place
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode token private key: %w", err)
	}
	//PEM is a base-64 encoding mechanism of a DER certificate. PEM can also encode other kinds of data,
	//such as public/private keys and certificate requests.
	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)

	if err != nil {
		return nil, fmt.Errorf("create: parse token private key: %w", err)
	}

	atClaims := make(jwt.MapClaims) // Claims are statements about an entity (typically, the user) and additional data.
	atClaims["sub"] = userid
	atClaims["token_uuid"] = td.TokenUuid
	atClaims["exp"] = td.ExpiresIn
	atClaims["iat"] = now.Unix()
	atClaims["nbf"] = now.Unix()

	//using the claims map jwt is signed with the RS 256 bit algorithm
	//signing is done with the help of RSA private key decoded above.
	*td.Token, err = jwt.NewWithClaims(jwt.SigningMethodRS256, atClaims).SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("create: sign token: %w", err)
	}

	return td, nil
}

// ValidateToken example from docs go-jwt
func ValidateToken(token string, publicKey string) (*TokenDetails, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey) //token string
	if err != nil {
		return nil, fmt.Errorf("could not decode: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)

	if err != nil {
		return nil, fmt.Errorf("validate: parse key: %w", err)
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("validate: invalid token")
	}

	return &TokenDetails{
		TokenUuid: fmt.Sprint(claims["token_uuid"]),
		UserID:    fmt.Sprint(claims["sub"]),
	}, nil
}
