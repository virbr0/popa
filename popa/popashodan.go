package popa

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type ShodanSearchResponse struct {
	Matches []struct {
		IPStr string `json:"ip_str"`
	} `json:"matches"`
}

func Search(apiKey string, favHash int, numPages int) []string {

	var ipMatches []string

	for page := 1; page <= numPages; page++ {
		fmt.Println("Getting results from Shodan - page: ", page)

		// Prepare the request URL with query parameters
		url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=http.favicon.hash:%d&page=%d&fields=ip_str&minify=false", apiKey, favHash, page)

		resp, err := http.Get(url)

		if err != nil {
			log.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Check if the HTTP response status is OK
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Failed to get a valid response: %s", resp.Status)
		}

		// Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Failed to read response body: %v", err)
		}

		// Parse the JSON response
		var searchResponse ShodanSearchResponse
		if err := json.Unmarshal(body, &searchResponse); err != nil {
			log.Fatalf("Failed to unmarshal JSON: %v", err)
		}

		// Extract IP addresses and append to slice
		for _, match := range searchResponse.Matches {
			ipMatches = append(ipMatches, match.IPStr)
		}

	}
	return ipMatches

}
