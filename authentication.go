package resource

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"time"
)

type Response struct {
	Token string
}

func GenerateAccessToken(s *Source, now time.Time) (string, error) {
	if s.AccessToken != "" {
		return s.AccessToken, nil
	}

	decode, _ := pem.Decode([]byte(s.PrivateKey))
	key, _ := x509.ParsePKCS1PrivateKey(decode.Bytes)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	cl := jwt.Claims{
		Issuer:   s.AppId,
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	signedJwt, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}

	var endpoint string
	if s.V3Endpoint != "" {
		endpoint = s.V3Endpoint
	} else {
		endpoint = "https://api.github.com"
	}
	request, err := http.NewRequest("POST", endpoint+"/app/installations/"+s.InstallationId+"/access_tokens", nil)
	if err != nil {
		panic(err)
	}
	request.Header.Add("Authorization", "Bearer "+signedJwt)
	request.Header.Add("Accept", "application/vnd.github.machine-man-preview+json")
	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		panic(err)
	}

	var r Response
	err = json.NewDecoder(response.Body).Decode(&r)
	if err != nil {
		panic(err)
	}

	return r.Token, nil
}
