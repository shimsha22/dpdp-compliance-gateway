package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	dlp "cloud.google.com/go/dlp/apiv2"
	"cloud.google.com/go/dlp/apiv2/dlppb"
)

// The structure of our legal compliance receipt
type AuditReceipt struct {
	Timestamp        string `json:"timestamp"`
	RowsProcessed    int    `json:"rowsProcessed"`
	AlgorithmVersion string `json:"algorithmVersion"`
	TransactionHash  string `json:"transactionHash"`
}

// Upgraded response structure to include the receipt
type SecureResponse struct {
	Status     string       `json:"status"`
	Message    string       `json:"message"`
	SecureText string       `json:"secureText"`
	Receipt    AuditReceipt `json:"receipt"`
}

const projectID = "dpdp-gateway-test"

// GenerateAuditReceipt builds the SHA-256 fingerprint for the transaction
func GenerateAuditReceipt(rawText string, safeText string) AuditReceipt {
	rows := strings.Count(rawText, "\n")
	if rows == 0 && len(rawText) > 0 {
		rows = 1
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	algo := "Google Cloud DLP v2 + Vigilant-Vault Enterprise Ruleset"

	// We mix the time, the rows, the engine, and the resulting text to create a unique fingerprint
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

// deidentifyData houses the core Google Cloud DLP masking rules
func deidentifyData(ctx context.Context, client *dlp.Client, text string) (string, error) {
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
