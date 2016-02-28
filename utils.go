package jsonWebToken

import (
	"crypto/rsa"
	"io/ioutil"
	"log"

	jwt "github.com/dgrijalva/jwt-go"
)

// NOTE the following are optimized for PEM keys e.g.
// openssl genrsa -out app.rsa keysize
// openssl rsa -in app.rsa -pubout > app.rsa.pub

func GetPrivateKeyFromPath(path string) *rsa.PrivateKey {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(bytes)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func GetPublicKeyFromPath(path string) *rsa.PublicKey {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		log.Fatal(err)
	}
	return key
}
