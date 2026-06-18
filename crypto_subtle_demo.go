// go run crypto_subtle_demo.go

package main

import (
	"crypto/subtle"
	"fmt"
)

// In a real application, this would be a hashed value or a secure API key.
const correctToken = "Then were the king's scribes called at that time in the third month, that is, the month Sivan, on the three and twentieth day thereof; and it was written according to all that Mordecai commanded unto the Jews, and to the lieutenants, and the deputies and rulers of the provinces which are from India unto Ethiopia, an hundred twenty and seven provinces, unto every province according to the writing thereof, and unto every people after their language, and to the Jews according to their writing, and according to their language"

func main() {
	// Simulated user inputs
	wrongTokenEarly := "Xhen were the king's scribes called at that time in the third month, that is, the month Sivan, on the three and twentieth day thereof; and it was written according to all that Mordecai commanded unto the Jews, and to the lieutenants, and the deputies and rulers of the provinces which are from India unto Ethiopia, an hundred twenty and seven provinces, unto every province according to the writing thereof, and unto every people after their language, and to the Jews according to their writing, and according to their language" // Fails on the 1st character
	wrongTokenLate := "Then were the king's scribes called at that time in the third month, that is, the month Sivan, on the three and twentieth day thereof; and it was written according to all that Mordecai commanded unto the Jews, and to the lieutenants, and the deputies and rulers of the provinces which are from India unto Ethiopia, an hundred twenty and seven provinces, unto every province according to the writing thereof, and unto every people after their language, and to the Jews according to their writing, and according to their languagX"  // Fails on the last character
	goodToken := "Then were the king's scribes called at that time in the third month, that is, the month Sivan, on the three and twentieth day thereof; and it was written according to all that Mordecai commanded unto the Jews, and to the lieutenants, and the deputies and rulers of the provinces which are from India unto Ethiopia, an hundred twenty and seven provinces, unto every province according to the writing thereof, and unto every people after their language, and to the Jews according to their writing, and according to their language"       // Perfect match

	fmt.Println("--- Standard Comparison (Vulnerable to Timing Attacks) ---")
	fmt.Printf("Early fail match: %v\n", vulnerableCompare(wrongTokenEarly, correctToken))
	fmt.Printf("Late fail match:  %v\n", vulnerableCompare(wrongTokenLate, correctToken))

	fmt.Println("\n--- Constant-Time Comparison (Secure) ---")
	fmt.Printf("Early fail match: %v\n", secureCompare(wrongTokenEarly, correctToken))
	fmt.Printf("Late fail match:  %v\n", secureCompare(wrongTokenLate, correctToken))
	fmt.Printf("Exact match:      %v\n", secureCompare(goodToken, correctToken))
}

// vulnerableCompare uses standard equality.
// It returns faster if the first character is wrong than if the last character is wrong.
func vulnerableCompare(input, target string) bool {
	return input == target
}

// secureCompare uses crypto/subtle to ensure the comparison time is uniform.
func secureCompare(input, target string) bool {
	inputBytes := []byte(input)
	targetBytes := []byte(target)

	// ConstantTimeCompare requires slices of equal length.
	// If lengths differ, we must still perform a constant-time operation
	// to avoid leaking the correct string's length.
	if len(inputBytes) != len(targetBytes) {
		// Compare target with itself to consume time, but ultimately return false
		subtle.ConstantTimeCompare(targetBytes, targetBytes)
		return false
	}

	// Returns 1 if equal, 0 if not.
	match := subtle.ConstantTimeCompare(inputBytes, targetBytes)
	return match == 1
}
