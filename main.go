package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/adampresley/gofavigrab/parser"
	"github.com/spaolacci/murmur3"
	"github.com/virbr0/popa/popa"
)

type URLContent struct {
	Body []byte
	Code int
}

func main() {
	var numPages int

	tgt := flag.String("t", "", "Set the target.")
	flag.IntVar(&numPages, "ps", 1, "Set max number of pages to search on Shodan.")
	apiKey := flag.String("k", "", "Set API key.")
	flag.Parse()

	flag.Usage = func() {
		fmt.Println("Usage:")
		flag.PrintDefaults()
	}

	if flag.NFlag() == 0 || *apiKey == "" {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("Target: ", *tgt)
	fmt.Println("Number of Shodan queries: ", numPages)

	if !strings.HasPrefix(*tgt, "http://") && !strings.HasPrefix(*tgt, "https://") {
		fmt.Println("Error: Target must begin with http:// or https://")
		os.Exit(1)
	}

	// Returns favHash
	favHash, targetContent := getTargetDetails(tgt)

	// Conduct a number of Shodan searches specified by -ps flag then return all found IP addresses
	ipMatches := popa.Search(*apiKey, favHash, numPages)

	// Check similarity of IP hits and target
	checkSimilar(ipMatches, targetContent)
}

func getURL(tgt *string) (*URLContent, error) {

	// Skip cert verification for IPs
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Creating the HTTP client
	client := &http.Client{
		Transport: transport,
	}

	// Create http req. todo: add multiple http verbs
	req, err := http.NewRequest("GET", *tgt, nil)

	// Set user-agent
	req.Header.Set("User-Agent", "popa")

	// Send HTTP request
	resp, err := client.Do(req)

	// Handle HTTP request failures
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		fmt.Println(err)
	}

	urlContent := &URLContent{
		Body: body,
		Code: resp.StatusCode,
	}

	return urlContent, err

}

func getTargetDetails(tgt *string) (int, *URLContent) {
	// This should grab all useful identifiers to help find potential matches.
	// Favicon, Response Size, Title

	targetContent, err := getURL(tgt)

	// Parse html to get favicon url.
	htmlParser := parser.NewHTMLParser(string(targetContent.Body))
	favURL, err := htmlParser.GetFaviconURL()

	if err != nil {
		fmt.Println("Favicon not found.", err)
	}

	fmt.Println("Favicon found:", favURL)

	fmt.Println("Target response code:", targetContent.Code)
	fmt.Println("Target response size:", len(targetContent.Body))

	// Check if favURL relative or absolute
	fullFav := favURL
	pattern := regexp.MustCompile(`^(http|https):\/\/[^\s/$.?#].[^\s]*$`)

	if !pattern.MatchString(favURL) {
		fullFav = fmt.Sprintf("%s%s", *tgt, favURL)
	}

	favContent, err := getURL(&fullFav)

	buffer := bytes.NewBuffer(favContent.Body)

	// Create the output file
	out, err := os.Create("favi.tmp")

	if err != nil {
		fmt.Println("Error:", err)
	}

	defer out.Close()

	// Copy the response body to the output file
	_, err = io.Copy(out, buffer)
	if err != nil {
		fmt.Println("Error:", err)
	}

	base64Encoded := base64.StdEncoding.EncodeToString(favContent.Body)

	// Insert new lines into b64 every 76 chars for Shodan
	re := regexp.MustCompile(`(.{1,76})`)
	newBase64Encoded := re.ReplaceAllString(base64Encoded, "$1\n")

	favHash := int(murmur3.Sum32([]byte(newBase64Encoded)))

	fmt.Printf("Favicon hash: %d\n", favHash)

	return favHash, targetContent
}

func checkSimilar(ipMatches []string, targetContent *URLContent) {

	for _, ip := range ipMatches {

		// Is ipv4 or v6? if contains ':' = v6 lol. Non standard port who?
		if strings.Contains(ip, ":") {
			ip = fmt.Sprintf("[%s]", ip)
		}

		// Format ip to url and test http. Check if host header provides higher similarity.
		url := "http://" + ip
		ipContent, err := getURL(&url)

		// Handle errors when trying to get content from URLs
		if err != nil {
			fmt.Printf("\033[31mFAILED - %s - %v\033[0m\n", url, err)
			continue
		}

		similarityResult := popa.CalcByteSimilarity(ipContent.Body, targetContent.Body)

		if err == nil {
			resultFormat := fmt.Sprintf("Similarity: %.4f - URL: %s - Length: %d\n", similarityResult, url, len(ipContent.Body))

			switch {

			case similarityResult > 95.0:
				fmt.Printf("\033[32m%s\033[0m", resultFormat)

			case similarityResult > 85:
				fmt.Printf("\033[33m%s\033[0m", resultFormat)

			case similarityResult <= 85:
				fmt.Printf("\033[38;5;208m%s\033[0m", resultFormat)

			case similarityResult < 70:
				fmt.Printf("\033[31m%s\033[0m", resultFormat)

			}

		}

	}

}
