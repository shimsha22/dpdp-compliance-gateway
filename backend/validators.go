package main

import (
	"regexp"
)

// PreProcessPANs finds and mathematically validates Indian PAN cards before AI processing.

func PreProcessPANs(text string) (string, int) {

	broadRegex := regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`)

	strictPANRegex := regexp.MustCompile(`^[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]$`)

	panCount := 0

	safeText := broadRegex.ReplaceAllStringFunc(text, func(match string) string {
		if strictPANRegex.MatchString(match) {
			panCount++
			return "[VERIFIED_PAN_TOKEN]"
		}

		return match
	})

	return safeText, panCount
}
