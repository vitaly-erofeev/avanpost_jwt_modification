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
	Key string `json:"key,omitempty"`
	Sso string `json:"sso,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Key: "",
		Sso: "",
	}
}

type JWTTranslator struct {
	next                http.Handler
	JWKs                *keyfunc.JWKS
	localPrivateKeyPath string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v, ctx: %+v\n", name, *config, ctx)

	if len(config.Key) == 0 {
		return nil, fmt.Errorf("key not defined")
	}
	if len(config.Sso) == 0 {
		return nil, fmt.Errorf("sso not defined")
	}

	jwks, err := keyfunc.Get(config.Sso, keyfunc.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %v", err)
	}

	return &JWTTranslator{
		next:                next,
		JWKs:                jwks,
		localPrivateKeyPath: config.Key,
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
	token, err := jwt.Parse(tokenStr, j.JWKs.Keyfunc)
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

	if len(sub) == 0 {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("invalid claims"))
		return
	}

	// тут вместо http-запроса можно сделать кеш или прямую работу с БД
	userID := getUserID(sub)
	if userID == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("user not found"))
		return
	}

	privateKey, err := os.ReadFile(j.localPrivateKeyPath)
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("failed to read private key"))
		return
	}

	// создаем новый токен
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
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

func getUserID(sub string) string {
	// здесь должен быть запрос к твоему сервису/БД
	// можно через http.Get(service + "/users/by-sub/" + sub)
	return "12345" // временно заглушка
}
