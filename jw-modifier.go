package avanpost_jwt_modification

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

type Config struct {
	AvanpostJWKS string `json:"avanpost_jwks"`
	LocalPrivKey string `json:"local_priv_key"`
	UserService  string `json:"user_service"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JWTTranslator struct {
	next         http.Handler
	avanpostJWKs *keyfunc.JWKS
	localPrivKey []byte
	userService  string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	jwks, err := keyfunc.Get(config.AvanpostJWKS, keyfunc.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to get Avanpost JWKS: %v", err)
	}

	privKey, err := os.ReadFile(config.LocalPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	return &JWTTranslator{
		next:         next,
		avanpostJWKs: jwks,
		localPrivKey: privKey,
		userService:  config.UserService,
	}, nil
}

func (j *JWTTranslator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("missing Authorization header"))
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenStr, j.avanpostJWKs.Keyfunc)
	if err != nil || !token.Valid {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("invalid token"))
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("invalid claims"))
		return
	}

	sub := fmt.Sprintf("%v", claims["sub"])

	// тут вместо http-запроса можно сделать кеш или прямую работу с БД
	userID := getUserID(j.userService, sub)
	if userID == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("user not found"))
		return
	}

	// создаем новый токен
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(j.localPrivKey)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	newClaims := jwt.MapClaims{
		"user_id": userID,
		"sub":     sub,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iss":     "local-gateway",
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, newClaims)
	signed, err := newToken.SignedString(privKey)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// заменяем заголовок
	req.Header.Set("Authorization", "Bearer "+signed)

	j.next.ServeHTTP(rw, req)
}

func getUserID(service, sub string) string {
	// здесь должен быть запрос к твоему сервису/БД
	// можно через http.Get(service + "/users/by-sub/" + sub)
	return "12345" // временно заглушка
}
