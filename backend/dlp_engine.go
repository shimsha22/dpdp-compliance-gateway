package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	dlp "cloud.google.com/go/dlp/apiv2"
	"cloud.google.com/go/dlp/apiv2/dlppb"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
)

type AuditReceipt struct {
	Timestamp        string `json:"timestamp"`
	RowsProcessed    int    `json:"rowsProcessed"`
	AlgorithmVersion string `json:"algorithmVersion"`
	TransactionHash  string `json:"transactionHash"`
}

type SecureResponse struct {
	Status     string       `json:"status"`
	Message    string       `json:"message"`
	SecureText string       `json:"secureText"`
	Receipt    AuditReceipt `json:"receipt"`
}

// getDLPClient handles the "Bypass" logic for Render vs Local
func getDLPClient(ctx context.Context) (*dlp.Client, error) {
	accessToken := os.Getenv("GCP_ACCESS_TOKEN")

	if accessToken != "" {
		log.Println("Production Mode: Using temporary Access Token.")
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: accessToken,
		})
		return dlp.NewClient(ctx, option.WithTokenSource(tokenSource))
	}

	log.Println("Development Mode: Using local Google CLI credentials.")
	return dlp.NewClient(ctx)
}

func GenerateAuditReceipt(rawText string, safeText string) AuditReceipt {
	rows := strings.Count(rawText, "\n")
	if rows == 0 && len(rawText) > 0 {
		rows = 1
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	algo := "Google Cloud DLP v2 + Vigilant-Vault Enterprise Ruleset"

	payload := fmt.Sprintf("%s|%d|%s|%s", timestamp, rows, algo, safeText)
	hash := sha256.Sum256([]byte(payload))
	hashString := hex.EncodeToString(hash[:])

	return AuditReceipt{
		Timestamp:        timestamp,
		RowsProcessed:    rows,
		AlgorithmVersion: algo,
		TransactionHash:  hashString,
	}
}

// Updated: This function now creates its own client using the helper
func deidentifyData(ctx context.Context, text string) (string, error) {
	_ = godotenv.Load() // Ignore error if .env doesn't exist in production

	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		return "", fmt.Errorf("GCP_PROJECT_ID not set")
	}

	// 🚀 USE THE SMART CLIENT HERE
	client, err := getDLPClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create dlp client: %v", err)
	}
	defer client.Close()

	req := &dlppb.DeidentifyContentRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global", projectID),
		InspectConfig: &dlppb.InspectConfig{
			InfoTypes: []*dlppb.InfoType{
				{Name: "PERSON_NAME"},
				{Name: "PHONE_NUMBER"},
				{Name: "EMAIL_ADDRESS"},
				{Name: "CREDIT_CARD_NUMBER"},
			},
		},
		DeidentifyConfig: &dlppb.DeidentifyConfig{
			Transformation: &dlppb.DeidentifyConfig_InfoTypeTransformations{
				InfoTypeTransformations: &dlppb.InfoTypeTransformations{
					Transformations: []*dlppb.InfoTypeTransformations_InfoTypeTransformation{
						{
							InfoTypes: []*dlppb.InfoType{{Name: "PHONE_NUMBER"}},
							PrimitiveTransformation: &dlppb.PrimitiveTransformation{
								Transformation: &dlppb.PrimitiveTransformation_CharacterMaskConfig{
									CharacterMaskConfig: &dlppb.CharacterMaskConfig{
										MaskingCharacter: "*",
										NumberToMask:     10,
										ReverseOrder:     false,
									},
								},
							},
						},
						{
							InfoTypes: []*dlppb.InfoType{{Name: "PERSON_NAME"}},
							PrimitiveTransformation: &dlppb.PrimitiveTransformation{
								Transformation: &dlppb.PrimitiveTransformation_CryptoHashConfig{
									CryptoHashConfig: &dlppb.CryptoHashConfig{
										CryptoKey: &dlppb.CryptoKey{
											Source: &dlppb.CryptoKey_Transient{
												Transient: &dlppb.TransientCryptoKey{Name: "vigilant-vault-key"},
											},
										},
									},
								},
							},
						},
						{
							InfoTypes: []*dlppb.InfoType{{Name: "EMAIL_ADDRESS"}},
							PrimitiveTransformation: &dlppb.PrimitiveTransformation{
								Transformation: &dlppb.PrimitiveTransformation_ReplaceConfig{
									ReplaceConfig: &dlppb.ReplaceValueConfig{
										NewValue: &dlppb.Value{Type: &dlppb.Value_StringValue{StringValue: "[SECURE_EMAIL]"}},
									},
								},
							},
						},
						{
							InfoTypes: []*dlppb.InfoType{{Name: "CREDIT_CARD_NUMBER"}},
							PrimitiveTransformation: &dlppb.PrimitiveTransformation{
								Transformation: &dlppb.PrimitiveTransformation_CharacterMaskConfig{
									CharacterMaskConfig: &dlppb.CharacterMaskConfig{
										MaskingCharacter: "*",
										NumberToMask:     12,
										ReverseOrder:     false,
									},
								},
							},
						},
					},
				},
			},
		},
		Item: &dlppb.ContentItem{DataItem: &dlppb.ContentItem_Value{Value: text}},
	}

	resp, err := client.DeidentifyContent(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetItem().GetValue(), nil
}
