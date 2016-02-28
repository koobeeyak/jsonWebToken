package jsonWebToken

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

const (
	myPrivKeyPath   = "/Users/kubiak/keys/app.rsa"
	myPublicKeyPath = "/Users/kubiak/keys/app.rsa.pub"
	keyBits         = 1024
)

func TestSignAndReadWithPath(test *testing.T) {
	t := NewToken()
	l := []int{100, 200, 300}
	s := []string{"this", "is", "a", "test"}
	stringIntoToken := "Testing String."
	t.AddData("brd", l)
	t.AddData("str", s)
	t.AddData("tst", stringIntoToken)
	t.SetPrivateKeyFromPath(myPrivKeyPath)
	tokenString, err := t.GenerateToken()
	if err != nil {
		test.Log(err)
		test.FailNow()
	} else {
		test.Log("Generated this tokenString:")
		test.Log(tokenString)
	}
	myPublicKey := GetPublicKeyFromPath(myPublicKeyPath)
	if _, ok := AuthorizeToken(tokenString, myPublicKey); !ok {
		test.Log("Can't authorize token: ", err)
		test.FailNow()
	}
	stringOutOfToken := GetFromToken(tokenString, myPublicKey, "tst")
	if stringOutOfToken != stringOutOfToken {
		test.Log("Claims do not match.")
		test.FailNow()
	}
	brands := GetFromToken(tokenString, myPublicKey, "brd")
	test.Log(brands)
	slice := GetFromToken(tokenString, myPublicKey, "str")
	test.Log(slice)
}

func TestSignAndReadWithKeyGen(test *testing.T) {
	t := NewToken()
	brandsIntoToken := []int{1, 2, 3}
	t.AddData("brd", brandsIntoToken)
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		test.Log(err)
		test.FailNow()
	}
	pub := priv.PublicKey
	t.SetPrivateKey(priv)
	tokenString, err := t.GenerateToken()
	if err != nil {
		test.Log(err)
		test.FailNow()
	} else {
		test.Log("Generated this tokenString:")
		test.Log(tokenString)
	}
	brandsOutOfToken := GetFromToken(tokenString, &pub, "brd")
	test.Logf("In: %v\n", brandsIntoToken)
	test.Logf("Out: %v\n", brandsOutOfToken)
}
