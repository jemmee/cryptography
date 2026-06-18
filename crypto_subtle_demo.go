// go run crypto_subtle_demo.go

package main

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"time"
)

func main() {
	// 1. Create a very long base string
	// This amplifies the timing difference between an early fail and a late fail.
	baseString := strings.Repeat("Then were the king's scribes called at that time in the third month, that is, the month Sivan, on the three and twentieth day thereof; and it was written according to all that Mordecai commanded unto the Jews, and to the lieutenants, and the deputies and rulers of the provinces which are from India unto Ethiopia, an hundred twenty and seven provinces, unto every province according to the writing thereof, and unto every people after their language, and to the Jews according to their writing, and according to their language", 2000)

	correctToken := baseString + "MATCH"
	wrongTokenEarly := "X" + baseString + "MATCH" // Fails on the very 1st character
	wrongTokenLate := baseString + "MATCX"        // Fails on the very last character

	// Number of iterations to make the time difference measurable
	// iterations := 5_000_000
	iterations := 10000

	fmt.Printf("Running each test %d times...\n\n", iterations)

	// ==========================================
	// Test 1: Standard Comparison (Vulnerable)
	// ==========================================
	fmt.Println("--- Standard Comparison (Vulnerable) ---")

	start := time.Now()
	for i := 0; i < iterations; i++ {
		_ = vulnerableCompare(wrongTokenEarly, correctToken)
	}
	earlyFailDuration := time.Since(start)
	fmt.Printf("Early Fail Time: %v\n", earlyFailDuration)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = vulnerableCompare(wrongTokenLate, correctToken)
	}
	lateFailDuration := time.Since(start)
	fmt.Printf("Late Fail Time:  %v\n", lateFailDuration)

	// Calculate the difference
	vulnDiff := lateFailDuration - earlyFailDuration
	fmt.Printf("↳ Time difference leaked: %v\n\n", vulnDiff)

	// ==========================================
	// Test 2: Constant-Time Comparison (Secure)
	// ==========================================
	fmt.Println("--- Constant-Time Comparison (Secure) ---")

	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = secureCompare(wrongTokenEarly, correctToken)
	}
	secureEarlyDuration := time.Since(start)
	fmt.Printf("Early Fail Time: %v\n", secureEarlyDuration)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = secureCompare(wrongTokenLate, correctToken)
	}
	secureLateDuration := time.Since(start)
	fmt.Printf("Late Fail Time:  %v\n", secureLateDuration)

	// Calculate the difference
	secureDiff := secureLateDuration - secureEarlyDuration
	if secureDiff < 0 {
		secureDiff = -secureDiff
	}
	fmt.Printf("↳ Time difference leaked: %v\n", secureDiff)
}

func vulnerableCompare(input, target string) bool {
	return input == target
}

func secureCompare(input, target string) bool {
	inputBytes := []byte(input)
	targetBytes := []byte(target)

	if len(inputBytes) != len(targetBytes) {
		subtle.ConstantTimeCompare(targetBytes, targetBytes)
		return false
	}

	match := subtle.ConstantTimeCompare(inputBytes, targetBytes)
	return match == 1
}
