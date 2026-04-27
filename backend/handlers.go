package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	vision "cloud.google.com/go/vision/apiv1"
	"google.golang.org/api/option"
)

func getVisionClient(ctx context.Context) (*vision.ImageAnnotatorClient, error) {
	// Synchronized with your DLP credentials variable
	credsJSON := os.Getenv("GCP_CREDS_JSON")
	if credsJSON != "" {
		return vision.NewImageAnnotatorClient(ctx, option.WithCredentialsJSON([]byte(credsJSON)))
	}
	return vision.NewImageAnnotatorClient(ctx)
}

func secureTextHandler(w http.ResponseWriter, r *http.Request) {
	var reqData struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		http.Error(w, "Invalid request: Could not parse JSON body.", http.StatusBadRequest)
		return
	}

	preProcessedText, customPanCount := PreProcessPANs(reqData.Text)

	ctx := context.Background()
	safeText, err := deidentifyData(ctx, preProcessedText)
	if err != nil {
		http.Error(w, "DLP Pipeline Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	receipt := GenerateAuditReceipt(reqData.Text, safeText)
	if customPanCount > 0 {
		receipt.AlgorithmVersion += " (Hybrid PAN Interception Active)"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SecureResponse{
		Status:     "Success",
		Message:    "Text secured.",
		SecureText: safeText,
		Receipt:    receipt,
	})
}

func secureImageHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	file, _, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Invalid request: Missing image file.", http.StatusBadRequest)
		return
	}
	defer file.Close()

	ctx := context.Background()
	visionClient, err := getVisionClient(ctx)
	if err != nil {
		http.Error(w, "System Error: Vision Client failed.", http.StatusInternalServerError)
		return
	}
	defer visionClient.Close()

	image, err := vision.NewImageFromReader(file)
	if err != nil {
		http.Error(w, "Invalid request: Could not read image.", http.StatusBadRequest)
		return
	}

	annotations, err := visionClient.DetectTexts(ctx, image, nil, 10)
	if err != nil {
		http.Error(w, "Vision Pipeline Failed.", http.StatusInternalServerError)
		return
	}

	extractedText := ""
	if len(annotations) > 0 {
		extractedText = annotations[0].Description
	}

	preProcessedText, customPanCount := PreProcessPANs(extractedText)

	safeText, err := deidentifyData(ctx, preProcessedText)
	if err != nil {
		http.Error(w, "DLP Pipeline Failed.", http.StatusInternalServerError)
		return
	}

	receipt := GenerateAuditReceipt(extractedText, safeText)
	if customPanCount > 0 {
		receipt.AlgorithmVersion += " (Hybrid PAN Interception Active)"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SecureResponse{
		Status:     "Success",
		Message:    "Image secured.",
		SecureText: safeText,
		Receipt:    receipt,
	})
}

func secureCSVHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	file, _, err := r.FormFile("csv")
	if err != nil {
		http.Error(w, "Invalid request: Missing CSV file.", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil || len(fileBytes) == 0 {
		http.Error(w, "Invalid request: Empty CSV.", http.StatusBadRequest)
		return
	}
	rawCSVText := string(fileBytes)

	preProcessedText, customPanCount := PreProcessPANs(rawCSVText)

	ctx := context.Background()
	safeCSVText, err := deidentifyData(ctx, preProcessedText)
	if err != nil {
		http.Error(w, "DLP Pipeline Failed.", http.StatusInternalServerError)
		return
	}

	receipt := GenerateAuditReceipt(rawCSVText, safeCSVText)
	if customPanCount > 0 {
		receipt.AlgorithmVersion += " (Hybrid PAN Interception Active)"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SecureResponse{
		Status:     "Success",
		Message:    "CSV batch processed.",
		SecureText: safeCSVText,
		Receipt:    receipt,
	})
}

func verifyAuditHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "Ready",
		"message": "Zero-Trust Verification Engine is active and listening.",
	})
}

func GenerateAuditReceipt(originalText string, securedText string) AuditReceipt {
	timestamp := time.Now().Format(time.RFC3339)
	// Calculate rows: split by newline and count
	rows := strings.Count(originalText, "\n")
	if len(originalText) > 0 && !strings.HasSuffix(originalText, "\n") {
		rows++
	}

	version := "v1.0-ZeroTrust"

	trimmedSecured := strings.TrimSpace(securedText)

	payload := fmt.Sprintf("%s|%d|%s|%s", timestamp, rows, version, trimmedSecured)

	hash := sha256.Sum256([]byte(payload))
	finalHash := hex.EncodeToString(hash[:])

	return AuditReceipt{
		Timestamp:        timestamp,
		RowsProcessed:    rows,
		AlgorithmVersion: version,
		TransactionHash:  finalHash,
	}
}
