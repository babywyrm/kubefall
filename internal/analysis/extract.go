package analysis

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

type ExtractedData struct {
	Tokens      []TokenInfo
	Credentials []Credential
	EnvVars     map[string]string
	Endpoints   []string
	Base64Data  []Base64Info
}

type TokenInfo struct {
	Type    string
	Value   string
	Valid   bool
	Claims  map[string]interface{}
}

type Credential struct {
	Type  string
	Key   string
	Value string
}

type Base64Info struct {
	Key   string
	Data  string
	Decoded string
}

func ExtractFromConfigMap(data string) *ExtractedData {
	extracted := &ExtractedData{
		Tokens:      []TokenInfo{},
		Credentials: []Credential{},
		EnvVars:     make(map[string]string),
		Endpoints:   []string{},
		Base64Data:  []Base64Info{},
	}

	var cm struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(data), &cm); err != nil {
		return extracted
	}

	for _, item := range cm.Items {
		for key, value := range item.Data {
			extracted.analyzeValue(key, value)
		}
	}

	return extracted
}

func ExtractFromSecret(data string) *ExtractedData {
	extracted := &ExtractedData{
		Tokens:      []TokenInfo{},
		Credentials: []Credential{},
		EnvVars:     make(map[string]string),
		Endpoints:   []string{},
		Base64Data:  []Base64Info{},
	}

	var secret struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(data), &secret); err != nil {
		return extracted
	}

	for _, item := range secret.Items {
		for key, value := range item.Data {
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err == nil {
				extracted.analyzeValue(key, string(decoded))
			} else {
				extracted.analyzeValue(key, value)
			}
		}
	}

	return extracted
}

func (e *ExtractedData) analyzeValue(key, value string) {
	lowerKey := strings.ToLower(key)

	if e.isToken(value) {
		token := TokenInfo{
			Type:  e.detectTokenType(value),
			Value: value,
		}
		if claims := parseJWT(value); claims != nil {
			token.Valid = true
			token.Claims = claims
		}
		e.Tokens = append(e.Tokens, token)
	}

	if e.isCredential(key, value) {
		e.Credentials = append(e.Credentials, Credential{
			Type:  e.detectCredentialType(key),
			Key:   key,
			Value: value,
		})
	}

	if strings.Contains(lowerKey, "url") || strings.Contains(lowerKey, "endpoint") || strings.Contains(lowerKey, "host") {
		if url := e.extractURL(value); url != "" {
			e.Endpoints = append(e.Endpoints, url)
		}
	}

	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) > 0 {
		e.Base64Data = append(e.Base64Data, Base64Info{
			Key:     key,
			Data:    value,
			Decoded: string(decoded),
		})
	}

	if strings.Contains(lowerKey, "env") || strings.Contains(lowerKey, "config") {
		e.EnvVars[key] = value
	}
}

func (e *ExtractedData) isToken(value string) bool {
	if len(value) < 50 {
		return false
	}

	jwtPattern := regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	if jwtPattern.MatchString(value) {
		return true
	}

	if strings.Contains(strings.ToLower(value), "bearer") {
		return true
	}

	return false
}

func (e *ExtractedData) detectTokenType(value string) string {
	if strings.HasPrefix(value, "eyJ") {
		return "JWT"
	}
	if strings.Contains(strings.ToLower(value), "bearer") {
		return "Bearer"
	}
	return "Unknown"
}

func (e *ExtractedData) isCredential(key, value string) bool {
	lowerKey := strings.ToLower(key)
	credentialKeys := []string{"password", "passwd", "pwd", "secret", "key", "token", "api_key", "apikey", "auth", "credential"}
	
	for _, credKey := range credentialKeys {
		if strings.Contains(lowerKey, credKey) {
			return true
		}
	}

	if len(value) > 8 && len(value) < 200 {
		if matched, _ := regexp.MatchString(`^[A-Za-z0-9+/=]+$`, value); matched {
			return true
		}
	}

	return false
}

func (e *ExtractedData) detectCredentialType(key string) string {
	lowerKey := strings.ToLower(key)
	if strings.Contains(lowerKey, "password") {
		return "Password"
	}
	if strings.Contains(lowerKey, "api") {
		return "API Key"
	}
	if strings.Contains(lowerKey, "token") {
		return "Token"
	}
	return "Credential"
}

func (e *ExtractedData) extractURL(value string) string {
	urlPattern := regexp.MustCompile(`https?://[^\s"']+`)
	if match := urlPattern.FindString(value); match != "" {
		return match
	}
	return ""
}

func parseJWT(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	return claims
}

