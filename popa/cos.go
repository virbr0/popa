package popa

import (
	"math"
)

func CalcByteSimilarity(tgtContent, ipContent []byte) float64 {

	// todo: also calculate content similarity. strip a few html tags and calc
	// Create byte frequency maps
	freq1 := make(map[byte]int)
	freq2 := make(map[byte]int)

	for _, b := range tgtContent {
		freq1[b]++
	}
	for _, b := range ipContent {
		freq2[b]++
	}

	// Calculate cosine similarity
	// ChatGPT hook me uppp
	dotProduct := 0.0
	magnitude1 := 0.0
	magnitude2 := 0.0

	for b := 0; b <= 255; b++ {
		count1 := float64(freq1[byte(b)])
		count2 := float64(freq2[byte(b)])
		dotProduct += count1 * count2
		magnitude1 += count1 * count1
		magnitude2 += count2 * count2
	}

	if magnitude1 == 0 || magnitude2 == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(magnitude1) * math.Sqrt(magnitude2)) * 100
}
