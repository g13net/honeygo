package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

var (
	Token  string
	ChatID string
)

func SendTelegramMessage(message string) {
	// Sanitize inputs first
	cleanToken := strings.TrimSpace(Token)
	cleanToken = strings.Trim(cleanToken, "\"'`")
	if strings.HasPrefix(strings.ToLower(cleanToken), "bot") {
		cleanToken = cleanToken[3:] // Remove "bot" prefix if user accidentally included it
	}

	cleanChatID := strings.TrimSpace(ChatID)
	cleanChatID = strings.Trim(cleanChatID, "\"'`")

	if cleanToken == "" || cleanChatID == "" {
		return // Alerting not configured
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cleanToken)

	payload := map[string]string{
		"chat_id":    cleanChatID,
		"text":       message,
		"parse_mode": "Markdown",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal telegram payload: %v", err)
		return
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Failed to send telegram alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("Telegram API returned non-OK status: %s, body: %s", resp.Status, string(respBody))
	}
}
