package main

import (
	"context"
	"fmt"
	"log"
	"os"

	dlp "cloud.google.com/go/dlp/apiv2"
	"cloud.google.com/go/dlp/apiv2/dlppb"
	"github.com/joho/godotenv"
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

func getDLPClient(ctx context.Context) (*dlp.Client, error) {

	credsJSON := os.Getenv("GCP_CREDS_JSON")

	if credsJSON != "" {
		log.Println("Production Mode: Using Service Account Credentials from Environment.")
		return dlp.NewClient(ctx, option.WithCredentialsJSON([]byte(credsJSON)))
	}

	log.Println("Development Mode: Using local default credentials.")
	return dlp.NewClient(ctx)
}

func deidentifyData(ctx context.Context, text string) (string, error) {
	_ = godotenv.Load()

	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		return "", fmt.Errorf("FATAL: GCP_PROJECT_ID not set in environment")
	}
	client, err := getDLPClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create DLP client: %v", err)
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
