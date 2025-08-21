package avanpost_jwt_modification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

type Config struct {
	Key         string `json:"key,omitempty"`
	Sso         string `json:"sso,omitempty"`
	UserService string `json:"userservice,omitempty"` // URL сервиса для получения пользователя
	ApiKey      string `json:"apikey,omitempty"`      // API ключ для запроса к бэкенду
}

func CreateConfig() *Config {
	return &Config{
		Key:         "",
		Sso:         "",
		UserService: "",
		ApiKey:      "",
	}
}

type JWTTranslator struct {
	next       http.Handler
	JWKs       *keyfunc.JWKS
	privateKey []byte
	cfg        *Config
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v\n", name, *config)

	if config.Key == "" {
		return nil, fmt.Errorf("key not defined")
	}
	if config.Sso == "" {
		return nil, fmt.Errorf("sso not defined")
	}
	if config.UserService == "" {
		return nil, fmt.Errorf("user_service not defined")
	}
	if config.ApiKey == "" {
		return nil, fmt.Errorf("api_key not defined")
	}

	jwks, err := keyfunc.Get(config.Sso, keyfunc.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %v", err)
	}

	privateKey, err := os.ReadFile(config.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	return &JWTTranslator{
		next:       next,
		JWKs:       jwks,
		privateKey: privateKey,
		cfg:        config,
	}, nil
}

func (j *JWTTranslator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(rw, "missing Authorization header", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenStr, j.JWKs.Keyfunc)
	if token == nil {
		http.Error(rw, "invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(rw, "invalid claims", http.StatusUnauthorized)
		return
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		http.Error(rw, "invalid sub in claims", http.StatusUnauthorized)
		return
	}

	var name, midName, surName, login, email string

	if v, ok := claims["given_name"].(string); ok {
		name = v
	}
	if v, ok := claims["middle_name"].(string); ok {
		midName = v
	}
	if v, ok := claims["family_name"].(string); ok {
		surName = v
	}
	if v, ok := claims["preferred_username"].(string); ok {
		login = v
	}
	if v, ok := claims["email"].(string); ok {
		email = v
	}

	userData := UserData{
		sub:     sub,
		Name:    name,
		MidName: midName,
		SurName: surName,
		Login:   login,
		Email:   email,
	}

	user, err := j.getUserData(userData)
	if err != nil {
		http.Error(rw, "failed to get user data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		http.Error(rw, "failed to parse private key", http.StatusInternalServerError)
		return
	}

	newClaims := jwt.MapClaims{
		"user": user,
		"sub":  sub,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iss":  "local-gateway",
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, newClaims)
	signed, err := newToken.SignedString(privKey)
	if err != nil {
		http.Error(rw, "failed to sign new token", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", signed)
	j.next.ServeHTTP(rw, req)
}

type User struct {
	ID     int `json:"id"`
	RoleID int `json:"role_id"`
}

type UserData struct {
	sub     string `json:"sub"`
	Name    string `json:"name"`
	MidName string `json:"midname"`
	SurName string `json:"surname"`
	Login   string `json:"login"`
	Email   string `json:"email"`
}

func (j *JWTTranslator) getUserData(data UserData) (*User, error) {
	// идём на бэкенд
	// marshall data to json (like json_encode)
	marshalled, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("impossible to marshall UserData: %s", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", j.cfg.UserService, data.sub), bytes.NewReader(marshalled))
	if err != nil {
		return nil, fmt.Errorf("failed to create backend request: %w", err)
	}
	req.Header.Set("X-Api-Key", j.cfg.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("backend request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backend returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read backend response: %w", err)
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse backend response: %w", err)
	}

	return &user, nil
}
