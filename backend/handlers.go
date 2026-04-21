package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	dlp "cloud.google.com/go/dlp/apiv2"
	vision "cloud.google.com/go/vision/apiv1"
)

// --- TEXT HANDLER ---
func secureTextHandler(w http.ResponseWriter, r *http.Request) {
	var reqData struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		http.Error(w, "Invalid request: Could not parse JSON body.", http.StatusBadRequest)
		return
	}

	// 1. HYBRID INTERCEPTION: Run custom Go PAN validator
	preProcessedText, customPanCount := PreProcessPANs(reqData.Text)

	// 2. AI PIPELINE: Send to Google Cloud DLP
	ctx := context.Background()
	client, err := dlp.NewClient(ctx)
	if err != nil {
		http.Error(w, "Internal System Error: Could not connect to Google Cloud.", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	safeText, err := deidentifyData(ctx, client, preProcessedText)
	if err != nil {
		http.Error(w, "DLP Pipeline Failed: Unable to process text securely.", http.StatusInternalServerError)
		return
	}

	// 3. RECEIPT GENERATION
	receipt := GenerateAuditReceipt(reqData.Text, safeText)
	if customPanCount > 0 {
		receipt.AlgorithmVersion += " (Hybrid PAN Interception Active)"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SecureResponse{Status: "Success", Message: "Text secured.", SecureText: safeText, Receipt: receipt})
}

// --- IMAGE HANDLER ---
func secureImageHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20) // 10 MB limit
	file, _, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Invalid request: Missing or corrupted image file.", http.StatusBadRequest)
		return
	}
	defer file.Close()

	ctx := context.Background()
	visionClient, err := vision.NewImageAnnotatorClient(ctx)
	if err != nil {
		http.Error(w, "Internal System Error: Could not connect to Google Vision.", http.StatusInternalServerError)
		return
	}
	defer visionClient.Close()

	image, err := vision.NewImageFromReader(file)
	if err != nil {
		http.Error(w, "Invalid request: Could not read image data.", http.StatusBadRequest)
		return
	}

	annotations, err := visionClient.DetectTexts(ctx, image, nil, 10)
	if err != nil {
		http.Error(w, "Vision Pipeline Failed: Could not extract text from image.", http.StatusInternalServerError)
		return
	}

	extractedText := ""
	if len(annotations) > 0 {
		extractedText = annotations[0].Description
	}

	// 1. HYBRID INTERCEPTION
	preProcessedText, customPanCount := PreProcessPANs(extractedText)

	// 2. AI PIPELINE
	dlpClient, err := dlp.NewClient(ctx)
	if err != nil {
		http.Error(w, "Internal System Error: Could not connect to Google Cloud DLP.", http.StatusInternalServerError)
		return
	}
	defer dlpClient.Close()

	safeText, err := deidentifyData(ctx, dlpClient, preProcessedText)
	if err != nil {
		http.Error(w, "DLP Pipeline Failed: Unable to process extracted text securely.", http.StatusInternalServerError)
		return
	}

	// 3. RECEIPT GENERATION
	receipt := GenerateAuditReceipt(extractedText, safeText)
	if customPanCount > 0 {
		receipt.AlgorithmVersion += " (Hybrid PAN Interception Active)"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SecureResponse{Status: "Success", Message: "Image digitized and secured.", SecureText: safeText, Receipt: receipt})
}

// --- CSV BATCH HANDLER ---
func secureCSVHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	file, _, err := r.FormFile("csv")
	if err != nil {
		http.Error(w, "Invalid request: Missing or corrupted CSV file.", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil || len(fileBytes) == 0 {
		http.Error(w, "Invalid request: File is completely empty or unreadable.", http.StatusBadRequest)
		return
	}
	rawCSVText := string(fileBytes)

	// 1. HYBRID INTERCEPTION
	preProcessedText, customPanCount := PreProcessPANs(rawCSVText)

	// 2. AI PIPELINE
	ctx := context.Background()
	client, err := dlp.NewClient(ctx)
	if err != nil {
		http.Error(w, "Internal System Error: Could not connect to Google Cloud.", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	safeCSVText, err := deidentifyData(ctx, client, preProcessedText)
	if err != nil {
		http.Error(w, "DLP Pipeline Failed: Unable to process document securely.", http.StatusInternalServerError)
		return
	}

	// 3. RECEIPT GENERATION
	receipt := GenerateAuditReceipt(rawCSVText, safeCSVText)
	if customPanCount > 0 {
		receipt.AlgorithmVersion += " (Hybrid PAN Interception Active)"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SecureResponse{
		Status:     "Success",
		Message:    "CSV batch processed with Hybrid Ruleset.",
		SecureText: safeCSVText,
		Receipt:    receipt,
	})
}
