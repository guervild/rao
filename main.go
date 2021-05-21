package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type Parser struct {
	Url          string
	Technologies []string
}

func analyzeResponse(url string, content *bufio.Reader) *Parser {

	resp, err := http.ReadResponse(content, nil)

	if err != nil {
		log.Printf("[!] Error HTTP: %s\n", err)
		return nil
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Printf("[!] Error READ : %s\n", err)
		return nil
	}

	wappalyzerClient, err := wappalyzer.New()
	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)

	var technologies []string

	for match := range fingerprints {
		technologies = append(technologies, match)
	}

	p := Parser{
		Url:          url,
		Technologies: technologies,
	}

	return &p
}

func (p *Parser) ToString() string {

	var output strings.Builder

	output.WriteString(fmt.Sprintf("%s - ", p.Url))

	var techno string

	output.WriteString("[")

	if len(p.Technologies) > 0 {
		techno = strings.Join(p.Technologies, ", ")
		output.WriteString(techno)
	}

	output.WriteRune(']')

	return output.String()
}

func parseMegFile(input *os.File) (string, *bufio.Reader) {
	sc := bufio.NewScanner(input)

	sc.Scan()

	url := strings.Trim(sc.Text(), "\n")

	var line string

	//Pass header and first empty line
	for i := 0; i < 2; i++ {
		for sc.Scan() {

			line = sc.Text()

			if line == "" || len(line) == 0 {
				break
			}

		}
	}

	//Replace the response part to get clean headers
	m1 := regexp.MustCompile(`^(< )`)

	var builder strings.Builder

	for sc.Scan() {
		line = sc.Text()
		if line == "" || len(line) == 0 {
			break
		}

		if !strings.Contains(line, "Content-Length") {
			builder.WriteString(m1.ReplaceAllString(line, "") + "\n")
		}
	}

	// Add missing newline to get a correct http response
	builder.WriteString("\r\n")

	// Add body to builder string
	for sc.Scan() {
		line = sc.Text()

		builder.WriteString(line + "\n")
	}

	content := bufio.NewReader(strings.NewReader(builder.String()))

	return url, content
}

func parseCurlFile(input *os.File) (string, *bufio.Reader) {

	temp := bufio.NewScanner(input)
	var url string

	m1 := regexp.MustCompile(`[Ll]ocation: (.*)`)
	m2 := regexp.MustCompile(`host-header: (.*)`)
	//m3 := regexp.MustCompile(`[sS]erver: (.*)`)

	var builder strings.Builder

	for temp.Scan() {
		line := temp.Text()

		if url == "" {
			lowerLine := strings.ToLower(line)
			if strings.Contains(lowerLine, "location:") {
				rs := m1.FindStringSubmatch(line)
				url = rs[1]
			} else if strings.Contains(lowerLine, "host-header:") {
				rs := m2.FindStringSubmatch(lowerLine)
				url = rs[1]
			}
			//could be an option to get url
			/* else if strings.Contains(lowerLine, "server:") {
				rs := m3.FindStringSubmatch(lowerLine)
				url = rs[1]
			}*/
		}

		if strings.Contains(line, "HTTP/2") {
			builder.WriteString("HTTP/2.0 200\n")

		} else {
			builder.WriteString(line + "\n")
		}
	}

	content := bufio.NewReader(strings.NewReader(builder.String()))

	return url, content
}

func main() {

	file := os.Stdin

	//if handle empty file is needed
	/*fi, err := file.Stat()

	if err != nil {
		log.Fatal("[!] Error with input file : %s\n", err)
	}

	size := fi.Size()
	if size == 0 {
		log.Fatal("[!] Error provided file is empty\n")
	}*/

	var format string
	flag.StringVar(&format, "format", "", "format of the file to be parsed")

	flag.Usage = func() {
		h := "Parse http response file\n\n"

		h += "Usage:\n"
		h += "  cat output.txt | ./rao -format <meg or curl>\n\n"

		h += "Options:\n"
		h += "  -format <meg or curl>          Set the format file to parse\n\n"
		h += "Examples:\n"
		h += "  cat out/github.com/56a9763339b64846c64d3cefdbd2ca40af0b9f2e | rao -format meg\n"
		h += "  curl -s -i -k https://gitlab.com | rao -format curl\n\n"

		fmt.Fprintf(os.Stderr, h)

	}

	flag.Parse()

	if format == "" || len(format) == 0 {
		log.Fatal("[!] format must be provided\n")
	}

	var url string
	var content *bufio.Reader

	switch format {

	case "meg":
		url, content = parseMegFile(file)

	case "curl":
		url, content = parseCurlFile(file)

	default:
		log.Fatal("[!] Unknown provided format\n")
	}

	parser := analyzeResponse(url, content)

	if parser == nil {
		log.Fatal("[!] Error while parsing response\n")
	}

	fmt.Println(parser.ToString())
}
