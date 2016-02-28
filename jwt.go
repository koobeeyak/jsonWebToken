package jsonWebToken

import (
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	expTime time.Duration = 1 * time.Hour
)

// I want to hide the implementation from the user, and allow the creation of tokens
// as a sort of API using the tokenData type
type tokenData struct {
	payload map[string]interface{}
	// one of the reserved jwt claims, "exp" should always be assigned
	expirationTimeToAdd time.Duration
	// how we sign the key
	encrytpionAlg jwt.SigningMethod
	privateKey    *rsa.PrivateKey
}

func (t *tokenData) AddData(key string, value interface{}) {
	t.payload[key] = value
}

func (t *tokenData) SetPrivateKeyFromPath(path string) {
	key := GetPrivateKeyFromPath(path)
	t.privateKey = key
}

func (t *tokenData) SetPrivateKey(key *rsa.PrivateKey) {
	t.privateKey = key
}

func (t *tokenData) SetExpiration(dur time.Duration) {
	t.expirationTimeToAdd = dur
}

func NewToken() tokenData {
	t := tokenData{}
	t.payload = make(map[string]interface{})

	// initialize every token with ecryption algorithm and expiration time
	t.encrytpionAlg = jwt.GetSigningMethod("RS256")
	t.expirationTimeToAdd = expTime
	return t
}

func (t *tokenData) GenerateToken() (tokenString string, err error) {
	token := jwt.New(t.encrytpionAlg)
	// always set an expiration from duration after time.Now()
	token.Claims["exp"] = time.Now().Add(t.expirationTimeToAdd)
	// populate token claims from t.payload
	for k, v := range t.payload {
		token.Claims[k] = v
	}
	tokenString, err = token.SignedString(t.privateKey)
	if err != nil {
		panic(err)
		return tokenString, err
	}
	return tokenString, nil
}

// _, ok := AuthorizeToken(tokenString, public)
func AuthorizeToken(tokenString string, publicKey *rsa.PublicKey) (*jwt.Token, bool) {
	// jwt.Parse expects tokenString extracted from http header and callback function which will return key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// check if we have proper encryption method first
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unmatched signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err == nil && token.Valid {
		return token, true
	}
	log.Println("Error: Token not valid.")
	log.Println(err)
	return nil, false
}

// brands := GetFromToken(tokenString, publicKey, "brands")
// will return nil if key doesn't exist as claim in token
func GetFromToken(tokenString string, publicKey *rsa.PublicKey, claim string) interface{} {
	token, ok := AuthorizeToken(tokenString, publicKey)
	if !ok {
		// NOTE as it is, even if token is not authorized it returns the same as if token is authorized and value is nil
		log.Println("Error: Token not valid.")
		return nil
	}
	value := token.Claims[claim]
	return value
}
