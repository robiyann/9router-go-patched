package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"9router/proxy/internal/log"
	"9router/proxy/internal/proxy"
)

const (
	stdAlphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	customAlphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"

	qoderRSAPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`
)

// Job Token cache (pat -> {jtToken, userId, expiresAt})
type jobTokenCacheEntry struct {
	token     string
	userID    string
	expiresAt time.Time
}

var (
	jobTokenCache   = make(map[string]jobTokenCacheEntry)
	jobTokenCacheMu sync.Mutex
)

// QoderEncodeBody encodes JSON body for Alibaba Cloud WAF bypass
func QoderEncodeBody(plainJSON []byte) []byte {
	stdB64 := base64.StdEncoding.EncodeToString(plainJSON)
	n := len(stdB64)
	if n == 0 {
		return []byte{}
	}
	a := n / 3

	// Rearrange: [tail][mid][head]
	rearranged := stdB64[n-a:] + stdB64[a:n-a] + stdB64[:a]

	var charMap [128]byte
	for i := 0; i < 64; i++ {
		charMap[stdAlphabet[i]] = customAlphabet[i]
	}
	charMap['='] = '$'

	out := make([]byte, n)
	for i := 0; i < n; i++ {
		c := rearranged[i]
		if c < 128 && charMap[c] != 0 {
			out[i] = charMap[c]
		} else {
			out[i] = c
		}
	}
	return out
}

func parseQoderPublicKey() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(qoderRSAPublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid Qoder RSA PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}
	return rsaPub, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func aesEncryptCBCBase64(plaintext []byte, key []byte) (string, error) {
	if len(key) != 16 {
		return "", fmt.Errorf("aes key must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, key)
	mode.CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func rsaEncryptBase64(data []byte) (string, error) {
	pub, err := parseQoderPublicKey()
	if err != nil {
		return "", err
	}
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

func exchangePATtoJobToken(ctx context.Context, client *http.Client, pat string) (string, string, error) {
	jobTokenCacheMu.Lock()
	if entry, ok := jobTokenCache[pat]; ok && time.Now().Before(entry.expiresAt) {
		jobTokenCacheMu.Unlock()
		return entry.token, entry.userID, nil
	}
	jobTokenCacheMu.Unlock()

	if client == nil {
		client = http.DefaultClient
	}

	// 1. Exchange PAT to Job Token
	reqBody, _ := json.Marshal(map[string]string{"personal_token": pat})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://openapi.qoder.sh/api/v1/jobToken/exchange", bytes.NewReader(reqBody))
	if err != nil {
		return "", "", fmt.Errorf("create exchange req: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cosy-Version", "1.1.13")
	req.Header.Set("Cosy-ClientType", "5")
	req.Header.Set("User-Agent", "qoder/1.1.13")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("do exchange req: %w", err)
	}
	defer resp.Body.Close()

	respBuf, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("exchange PAT failed (%d): %s", resp.StatusCode, string(respBuf))
	}

	var exData struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBuf, &exData); err != nil {
		return "", "", fmt.Errorf("unmarshal exchange resp: %w", err)
	}

	jobToken := exData.Data.Token
	if jobToken == "" {
		jobToken = exData.Token
	}
	if jobToken == "" {
		return "", "", fmt.Errorf("no jobToken in exchange response: %s", string(respBuf))
	}

	// 2. Fetch UserInfo
	uReq, err := http.NewRequestWithContext(ctx, "GET", "https://openapi.qoder.sh/api/v1/userinfo", nil)
	if err != nil {
		return "", "", fmt.Errorf("create userinfo req: %w", err)
	}
	uReq.Header.Set("Authorization", "Bearer "+jobToken)
	uReq.Header.Set("Cosy-Version", "1.1.13")
	uReq.Header.Set("User-Agent", "qoder/1.1.13")

	uResp, err := client.Do(uReq)
	if err != nil {
		return "", "", fmt.Errorf("do userinfo req: %w", err)
	}
	defer uResp.Body.Close()

	uBuf, _ := io.ReadAll(uResp.Body)
	var uData struct {
		Data struct {
			UserID string `json:"userId"`
			ID     string `json:"id"`
		} `json:"data"`
		UserID string `json:"userId"`
		ID     string `json:"id"`
	}
	_ = json.Unmarshal(uBuf, &uData)

	userID := uData.Data.UserID
	if userID == "" {
		userID = uData.Data.ID
	}
	if userID == "" {
		userID = uData.UserID
	}
	if userID == "" {
		userID = uData.ID
	}
	if userID == "" {
		userID = "user-" + uuid.New().String()[:8]
	}

	// Cache for 30 minutes
	jobTokenCacheMu.Lock()
	jobTokenCache[pat] = jobTokenCacheEntry{
		token:     jobToken,
		userID:    userID,
		expiresAt: time.Now().Add(30 * time.Minute),
	}
	jobTokenCacheMu.Unlock()

	return jobToken, userID, nil
}

// buildQoderCosyHeaders Step 5 Signing
func buildQoderCosyHeaders(encodedBody []byte, userID string, authToken string) (map[string]string, error) {
	if userID == "" {
		userID = "user-" + uuid.New().String()[:8]
	}
	if authToken == "" {
		authToken = "dt-" + uuid.New().String()
	}

	aesKeyStr := uuid.New().String()[:16]
	aesKey := []byte(aesKeyStr)

	userInfoJSON, err := json.Marshal(map[string]string{
		"uid":                  userID,
		"security_oauth_token": authToken,
		"name":                 "",
		"aid":                  "",
		"email":                "",
	})
	if err != nil {
		return nil, err
	}

	infoB64, err := aesEncryptCBCBase64(userInfoJSON, aesKey)
	if err != nil {
		return nil, err
	}

	cosyKey, err := rsaEncryptBase64(aesKey)
	if err != nil {
		return nil, err
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	reqID := uuid.New().String()

	payloadJSON := fmt.Sprintf(`{"version":"v1","requestId":"%s","info":"%s","cosyVersion":"1.1.13","ideVersion":""}`, reqID, infoB64)
	payloadB64 := base64.StdEncoding.EncodeToString([]byte(payloadJSON))

	sigPath := "/api/v2/service/pro/sse/agent_chat_generation"
	sigInput := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", payloadB64, cosyKey, timestamp, string(encodedBody), sigPath)
	sig := fmt.Sprintf("%x", md5.Sum([]byte(sigInput)))

	machineID := uuid.New().String()
	bodyHash := fmt.Sprintf("%x", md5.Sum(encodedBody))
	bodyLength := fmt.Sprintf("%d", len(encodedBody))

	headers := map[string]string{
		"Authorization":          fmt.Sprintf("Bearer COSY.%s.%s", payloadB64, sig),
		"Cosy-Key":               cosyKey,
		"Cosy-User":              userID,
		"Cosy-Date":              timestamp,
		"Cosy-Version":           "1.1.13",
		"Cosy-Machineid":         machineID,
		"Cosy-Machinetoken":      machineID,
		"Cosy-Machinetype":       "desktop",
		"Cosy-Machineos":         "windows",
		"Cosy-Clienttype":        "5",
		"Cosy-Clientip":          "127.0.0.1",
		"Cosy-Bodyhash":          bodyHash,
		"Cosy-Bodylength":        bodyLength,
		"Cosy-Sigpath":           sigPath,
		"Cosy-Data-Policy":       "true",
		"Login-Version":          "1.1.13",
		"X-Request-Id":           uuid.New().String(),
		"Content-Type":           "application/json",
		"Accept":                 "text/event-stream",
		"Accept-Encoding":        "identity",
	}

	return headers, nil
}

// prepareQoderFullPayload transforms OpenAI chat completion request to Qoder full envelope payload
func prepareQoderFullPayload(rawBody []byte, reqModel string) []byte {
	var reqMap map[string]any
	if err := json.Unmarshal(rawBody, &reqMap); err != nil {
		return rawBody
	}

	messages, _ := reqMap["messages"].([]any)
	var systemTexts []string
	var cleanedMessages []map[string]any
	var latestUserText string

	for _, m := range messages {
		msgMap, ok := m.(map[string]any)
		if !ok {
			continue
		}
		role, _ := msgMap["role"].(string)
		if role == "system" {
			if content, ok := msgMap["content"].(string); ok && content != "" {
				systemTexts = append(systemTexts, content)
			}
			continue
		}
		if role == "user" {
			if content, ok := msgMap["content"].(string); ok {
				latestUserText = content
			}
		}
		cleanedMessages = append(cleanedMessages, msgMap)
	}

	// Pure Natural Hoisting (Tanpa Prefix / Addition Text)
	if len(systemTexts) > 0 {
		hoistedText := strings.Join(systemTexts, "\n\n")
		firstUserFound := false
		for i, m := range cleanedMessages {
			if r, _ := m["role"].(string); r == "user" {
				if existingContent, ok := m["content"].(string); ok && existingContent != "" {
					cleanedMessages[i]["content"] = hoistedText + "\n\n" + existingContent
				} else {
					cleanedMessages[i]["content"] = hoistedText
				}
				firstUserFound = true
				break
			}
		}
		if !firstUserFound {
			syntheticUser := map[string]any{
				"role":    "user",
				"content": hoistedText,
			}
			cleanedMessages = append([]map[string]any{syntheticUser}, cleanedMessages...)
		}
	}

	modelKey := reqModel
	if strings.Contains(modelKey, "/") {
		parts := strings.SplitN(modelKey, "/", 2)
		modelKey = parts[1]
	}
	if modelKey == "" {
		modelKey = "efficient"
	}

	recID := uuid.New().String()
	sessID := uuid.New().String()

	fullPayload := map[string]any{
		"request_id":     uuid.New().String(),
		"request_set_id": recID,
		"chat_record_id": recID,
		"session_id":     sessID,
		"stream":         true,
		"chat_task":      "FREE_INPUT",
		"is_reply":       true,
		"is_retry":       false,
		"source":         1,
		"version":        "3",
		"session_type":   "qodercli",
		"agent_id":       "agent_common",
		"task_id":        "common",
		"code_language":  "",
		"chat_prompt":    "",
		"image_urls":     nil,
		"chat_context": map[string]any{
			"chatPrompt": "",
			"imageUrls":  nil,
			"extra": map[string]any{
				"context":         []any{},
				"modelConfig":     map[string]any{"key": modelKey, "is_reasoning": false},
				"originalContent": latestUserText,
			},
			"features": []any{},
			"text":     latestUserText,
		},
		"model_config": map[string]any{
			"key":              modelKey,
			"display_name":     modelKey,
			"is_vl":            false,
			"is_reasoning":     false,
			"max_input_tokens": 128000,
			"format":           "openai",
			"source":           "system",
		},
		"system":     "",
		"messages":   cleanedMessages,
		"parameters": map[string]any{"max_tokens": 4096},
	}

	out, err := json.Marshal(fullPayload)
	if err != nil {
		return rawBody
	}
	return out
}

// ForwardQoder handles requests for Qoder using Step 1-6 pipeline.
func ForwardQoder(w http.ResponseWriter, req *Request) error {
	ctx := req.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	authToken := req.APIKey
	userID := ""

	// Step 1: PAT Exchange to Job Token if pt-...
	if strings.HasPrefix(authToken, "pt-") {
		jt, uid, err := exchangePATtoJobToken(ctx, req.Client, authToken)
		if err != nil {
			log.Error("qoder", "PAT exchange failed", "error", err)
			return &proxy.UpstreamError{
				StatusCode: http.StatusUnauthorized,
				Body:       []byte(fmt.Sprintf(`{"error":{"message":"Qoder PAT exchange failed: %v","type":"authentication_error"}}`, err)),
			}
		}
		authToken = jt
		userID = uid
	}

	// Step 2: Endpoint URL determination
	targetURL := "https://api3.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	if strings.HasPrefix(authToken, "jt-") {
		targetURL = "https://api2.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	}

	// Step 3: Message Normalization & System Instruction Hoisting + Qoder Envelope Building
	normalizedBody := prepareQoderFullPayload(req.Body, req.ModelName)

	// Step 4: QoderEncodeBody WAF Bypass
	encodedBody := QoderEncodeBody(normalizedBody)

	// Step 5: COSY Headers Signing
	headers, err := buildQoderCosyHeaders(encodedBody, userID, authToken)
	if err != nil {
		return fmt.Errorf("build Qoder COSY headers: %w", err)
	}

	client := req.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := proxy.DoRequest(ctx, client, "POST", targetURL, headers, encodedBody)
	if err != nil {
		return fmt.Errorf("ForwardQoder do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBuf, _ := io.ReadAll(resp.Body)
		return &proxy.UpstreamError{
			StatusCode: resp.StatusCode,
			Body:       respBuf,
		}
	}

	// Step 6: SSE Unwrapping & Billing Check (StatusCode != 200 or code 112/10605 -> 403)
	if req.IsStream {
		return handleQoderSSE(w, resp.Body, req)
	}
	return handleQoderNonStream(w, resp.Body, req)
}

// handleQoderNonStream collects SSE text chunks and outputs a single JSON response
func handleQoderNonStream(w http.ResponseWriter, body io.Reader, req *Request) error {
	scanner := bufio.NewScanner(body)
	var fullText string
	var lastChunk string
	firstFrameProcessed := false

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}

		dataContent := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataContent == "" {
			continue
		}

		var envelope struct {
			StatusCodeValue int    `json:"statusCodeValue"`
			Body            string `json:"body"`
			Code            any    `json:"code"`
		}

		if err := json.Unmarshal([]byte(dataContent), &envelope); err != nil {
			continue
		}

		if !firstFrameProcessed {
			firstFrameProcessed = true
			if (envelope.StatusCodeValue != 0 && envelope.StatusCodeValue != 200) ||
				strings.Contains(dataContent, `"code":"112"`) ||
				strings.Contains(dataContent, `"code":112`) ||
				strings.Contains(dataContent, `"code":"10605"`) ||
				strings.Contains(dataContent, `"code":10605`) ||
				strings.Contains(dataContent, "pricingUrl") {
				log.Warn("qoder", "billing block or error detected in SSE envelope", "code", envelope.Code, "status", envelope.StatusCodeValue)
				return &proxy.UpstreamError{
					StatusCode: http.StatusForbidden,
					Body:       []byte(fmt.Sprintf(`{"error":{"message":"Qoder Billing Block / Quota Exceeded (403): %s","type":"insufficient_quota","code":"112"}}`, dataContent)),
				}
			}
		}

		innerBody := envelope.Body
		if innerBody == "" || strings.TrimSpace(innerBody) == "[DONE]" {
			continue
		}

		innerBody = strings.ReplaceAll(innerBody, "\r\n", "")
		lastChunk = innerBody

		var chunk struct {
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"delta"`
			} `json:"choices"`
		}

		if err := json.Unmarshal([]byte(innerBody), &chunk); err == nil {
			if len(chunk.Choices) > 0 {
				if chunk.Choices[0].Delta.Content != "" {
					fullText += chunk.Choices[0].Delta.Content
				}
			}
		}
	}

	// Create non-stream OpenAI response
	respObj := map[string]any{
		"id":      "chatcmpl-" + uuid.New().String(),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   req.ModelName,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": fullText,
				},
				"finish_reason": "stop",
			},
		},
	}

	respBytes, err := json.Marshal(respObj)
	if err != nil {
		return fmt.Errorf("marshal non-stream Qoder response: %w", err)
	}

	if req.ResponseBuf != nil {
		req.ResponseBuf.Write(respBytes)
	}

	if req.TranslateResp {
		return jsonResponse(req.Ctx, w, bytes.NewReader(respBytes), true, nil)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
	_ = lastChunk
	return nil
}
func handleQoderSSE(w http.ResponseWriter, body io.Reader, req *Request) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming not supported by response writer")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	scanner := bufio.NewScanner(body)
	firstFrameProcessed := false

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			if line != "" {
				fmt.Fprintf(w, "%s\n", line)
				flusher.Flush()
			}
			continue
		}

		dataContent := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataContent == "" {
			continue
		}

		var envelope struct {
			StatusCodeValue int    `json:"statusCodeValue"`
			Body            string `json:"body"`
			Code            any    `json:"code"`
		}

		if err := json.Unmarshal([]byte(dataContent), &envelope); err != nil {
			// If not envelope JSON, send verbatim
			fmt.Fprintf(w, "data: %s\n\n", dataContent)
			flusher.Flush()
			continue
		}

		// Billing Error Check on first frame or any frame
		if !firstFrameProcessed {
			firstFrameProcessed = true
			if (envelope.StatusCodeValue != 0 && envelope.StatusCodeValue != 200) ||
				strings.Contains(dataContent, `"code":"112"`) ||
				strings.Contains(dataContent, `"code":112`) ||
				strings.Contains(dataContent, `"code":"10605"`) ||
				strings.Contains(dataContent, `"code":10605`) ||
				strings.Contains(dataContent, "pricingUrl") {
				log.Warn("qoder", "billing block or error detected in SSE envelope", "code", envelope.Code, "status", envelope.StatusCodeValue)
				return &proxy.UpstreamError{
					StatusCode: http.StatusForbidden,
					Body:       []byte(fmt.Sprintf(`{"error":{"message":"Qoder Billing Block / Quota Exceeded (403): %s","type":"insufficient_quota","code":"112"}}`, dataContent)),
				}
			}
		}

		innerBody := envelope.Body
		if innerBody == "" {
			continue
		}

		// Clean newlines inside JSON string if any
		innerBody = strings.ReplaceAll(innerBody, "\r\n", "")

		// Keepalive / Done drop
		if strings.TrimSpace(innerBody) == "[DONE]" {
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			return nil
		}

		if req.ResponseBuf != nil {
			req.ResponseBuf.Write([]byte(innerBody))
		}

		fmt.Fprintf(w, "data: %s\n\n", innerBody)
		flusher.Flush()
	}

	return scanner.Err()
}
