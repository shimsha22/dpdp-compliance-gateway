package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	dlp "cloud.google.com/go/dlp/apiv2"
	"cloud.google.com/go/dlp/apiv2/dlppb"
)

// This holds your Google Cloud project ID
const projectID = "dpdp-gateway-test" // <--- UPDATE THIS

// 1. Define the shape of our incoming request (Like a Spring Boot DTO)
type SecureRequest struct {
	Text string `json:"text"`
}

// 2. Define the shape of our response
type SecureResponse struct {
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Findings []string `json:"findings"`
}

func main() {
	// Tell the server which URL path maps to which function
	http.HandleFunc("/api/secure", secureTextHandler)

	// Keep the server awake on port 8080
	fmt.Println("🚀 Vigilant-Vault API is running on http://localhost:8080")
	fmt.Println("Press Ctrl+C in the terminal to stop the server.")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Server crashed:", err)
	}
}

// 3. The actual API logic (Like your @PostMapping method)
func secureTextHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the JSON sent by the user
	var reqData SecureRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Connect to Google Cloud
	ctx := context.Background()
	client, err := dlp.NewClient(ctx)
	if err != nil {
		http.Error(w, "Failed to connect to Google", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	// Configure what to look for
	infoTypes := []*dlppb.InfoType{
		{Name: "INDIA_PAN_INDIVIDUAL"},
		{Name: "PERSON_NAME"},
		{Name: "PHONE_NUMBER"},
	}

	req := &dlppb.InspectContentRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global", projectID),
		InspectConfig: &dlppb.InspectConfig{
			InfoTypes: infoTypes,
		},
		Item: &dlppb.ContentItem{
			DataItem: &dlppb.ContentItem_Value{Value: reqData.Text},
		},
	}

	// Send to Google
	resp, err := client.InspectContent(ctx, req)
	if err != nil {
		http.Error(w, "Google API failed", http.StatusInternalServerError)
		return
	}

	// Format the response
	var detectedItems []string
	for _, f := range resp.GetResult().GetFindings() {
		detectedItems = append(detectedItems, fmt.Sprintf("Found [%s] (Confidence: %s)", f.GetInfoType().GetName(), f.GetLikelihood()))
	}

	finalResponse := SecureResponse{
		Status:   "Success",
		Message:  "Data scanned successfully",
		Findings: detectedItems,
	}

	// Send the JSON back to the user
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalResponse)
}
