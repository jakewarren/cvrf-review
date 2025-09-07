package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/jakewarren/cvrf-review/pkg/fortinet"
	"github.com/spf13/cobra"
)

//go:embed cvrf/fortinet
var fortinetData embed.FS

// product types the user is interested in
var productTypes []string

// product and version provided by the user for version specific queries
var (
	productName    string
	productVersion string
)

// the severity of vulnerabilities the user is interested in
var (
	severity     string
	minCvssScore float64
	maxCvssScore float64
)

var (
	jsonOutput         bool
	disableTableBorder bool
)

func severitytoCVSS(severity string) {
	switch strings.ToLower(severity) {
	case "critical":
		minCvssScore = 9.0
		maxCvssScore = 10.0
	case "high":
		minCvssScore = 7.0
		maxCvssScore = 8.9
	case "medium":
		minCvssScore = 4.0
		maxCvssScore = 6.9
	case "low":
		minCvssScore = 0.1
		maxCvssScore = 3.9
	}
}

var fortinetCmd = &cobra.Command{
	Use:   "fortinet",
	Short: "Get Fortinet vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		// set the severity filter values
		severitytoCVSS(severity)

		vulns, err := fortinet.GetAdvisories()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// loop through the advisories and collect the ones that match the filters
		matchingAdvisories := []fortinet.CVRF{}
		for _, v := range vulns {
			if filterCVRF(v) {
				matchingAdvisories = append(matchingAdvisories, v)
			}
		}

		// output the results
		if jsonOutput {
			// convert the CVRF to JSON
			j, _ := json.MarshalIndent(matchingAdvisories, "", "  ")

			fmt.Println(string(j))
		} else {
			for _, a := range matchingAdvisories {
				printCVRF(a)
			}
		}
	},
}

var fortinetVersionCmd = &cobra.Command{
	Use:   "affected",
	Short: "List vulnerabilities for a specific product version",
	Run: func(cmd *cobra.Command, args []string) {
		if productName == "" || productVersion == "" {
			fmt.Println("product and version are required")
			os.Exit(1)
		}

		// set the severity filter values
		severitytoCVSS(severity)

		matchingAdvisories, err := getAffectedAdvisories(productName, productVersion)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if len(matchingAdvisories) == 0 {
			fmt.Println("No matching advisories found.")
			return
		}

		if jsonOutput {
			j, _ := json.MarshalIndent(matchingAdvisories, "", "  ")
			fmt.Println(string(j))
		} else {
			for _, a := range matchingAdvisories {
				printCVRF(a)
			}
		}
	},
}

// getAffectedAdvisories loads cached Fortinet CVRF data and returns advisories
// affecting the specified product and version.
func getAffectedAdvisories(product, version string) ([]fortinet.CVRF, error) {
    base := "cvrf/fortinet"
    productID := fmt.Sprintf("%s-%s", strings.TrimSpace(product), strings.TrimSpace(version))

    // Use fs.Glob to avoid directory reads in WASM.
    // Matches paths like cvrf/fortinet/2024/FG-IR-XXXX-XXXX.json
    pattern := path.Join(base, "*", "*.json")
    fileList, err := fs.Glob(fortinetData, pattern)
    if err != nil {
        return nil, err
    }

    var matching []fortinet.CVRF
    for _, filePath := range fileList {
        data, err := fortinetData.ReadFile(filePath)
        if err != nil {
            return nil, err
        }

            normalized := string(data)
            normalized = strings.ReplaceAll(normalized, "cvrf-common:", "")
            normalized = strings.ReplaceAll(normalized, "cvrf:", "")
            normalized = strings.ReplaceAll(normalized, "\"@", "\"")
			normalized = strings.ReplaceAll(normalized, "\"#text\"", "\"text\"")

			var raw map[string]interface{}
			if err := json.Unmarshal([]byte(normalized), &raw); err != nil {
				return nil, err
			}
			doc, ok := raw["cvrfdoc"].(map[string]interface{})
			if !ok {
				return nil, errors.New("invalid cvrf document")
			}

			if vuln, ok := doc["Vulnerability"].(map[string]interface{}); ok {
				if cve, ok := vuln["CVE"]; ok {
					vuln["CVE"] = toStringSlice(cve)
				}
				if ps, ok := vuln["ProductStatuses"].(map[string]interface{}); ok {
					if status, ok := ps["Status"].(map[string]interface{}); ok {
						if pid, ok := status["ProductID"]; ok {
							status["ProductID"] = toStringSlice(pid)
						}
					}
				}
				if refs, ok := vuln["References"].(map[string]interface{}); ok {
					if r, ok := refs["Reference"]; ok {
						refs["Reference"] = toInterfaceSlice(r)
					}
				}
			}

			if notes, ok := doc["DocumentNotes"].(map[string]interface{}); ok {
				if n, ok := notes["Note"]; ok {
					notes["Note"] = toInterfaceSlice(n)
				}
			}
			if refs, ok := doc["DocumentReferences"].(map[string]interface{}); ok {
				if r, ok := refs["Reference"]; ok {
					refs["Reference"] = toInterfaceSlice(r)
				}
			}
			if ack, ok := doc["Acknowledgments"].(map[string]interface{}); ok {
				if a, ok := ack["Acknowledgment"]; ok {
					ack["Acknowledgment"] = toInterfaceSlice(a)
				}
			}

			if pt, ok := doc["ProductTree"].(map[string]interface{}); ok {
				pt = normalizeBranches(pt)
				if branches, ok := pt["Branch"].([]interface{}); ok && len(branches) == 1 {
					if bm, ok := branches[0].(map[string]interface{}); ok {
						pt["Branch"] = bm
					}
				}
				doc["ProductTree"] = pt
			}

			var advisory fortinet.CVRF
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				Result:  &advisory,
				TagName: "",
			})
			if err != nil {
				return nil, err
			}
			if err := decoder.Decode(doc); err != nil {
				return nil, err
			}

			if !contains(advisory.Vulnerability.ProductStatuses.Status.ProductID, productID) {
				continue
			}

            score, _ := strconv.ParseFloat(advisory.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3, 64)
            if score < minCvssScore || score > maxCvssScore {
                continue
            }

            matching = append(matching, advisory)
        }
    return matching, nil
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []interface{}:
		res := make([]string, 0, len(val))
		for _, s := range val {
			if str, ok := s.(string); ok {
				res = append(res, str)
			}
		}
		return res
	case []string:
		return val
	case string:
		return []string{val}
	default:
		return nil
	}
}

func toInterfaceSlice(v interface{}) []interface{} {
	switch val := v.(type) {
	case []interface{}:
		return val
	case map[string]interface{}:
		return []interface{}{val}
	default:
		return nil
	}
}

func normalizeBranches(m map[string]interface{}) map[string]interface{} {
	if b, ok := m["Branch"]; ok {
		switch bv := b.(type) {
		case []interface{}:
			for i, br := range bv {
				if bm, ok := br.(map[string]interface{}); ok {
					bv[i] = normalizeBranches(bm)
				}
			}
			m["Branch"] = bv
		case map[string]interface{}:
			m["Branch"] = []interface{}{normalizeBranches(bv)}
		}
	}
	return m
}

func contains(slice []string, target string) bool {
	for _, s := range slice {
		if strings.TrimSpace(s) == target {
			return true
		}
	}
	return false
}

// process the CVRF to determine if it matches any filters provided by the user. Returns true if the CVRF matches the filters and should be processed
func filterCVRF(advisory fortinet.CVRF) bool {
	// filter by severity
	cvssScore, _ := strconv.ParseFloat(advisory.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3, 64)

    // exclude vulnerabilities outside the user-defined inclusive range
    if cvssScore < minCvssScore || cvssScore > maxCvssScore {
        return false
    }

	// if the user provided a product type value to filter on, loop throught the product types and see if the product was affected by the advisory
	if len(productTypes) > 0 {
		matchedProduct := false
		for _, productType := range productTypes {
			for _, product := range advisory.ProductTree.Branch.Branch {
				if product.Name == productType {
					matchedProduct = true
				}
			}
		}
		if !matchedProduct {
			return false
		}
	}

	return true
}

func printCVRF(advisory fortinet.CVRF) {
	tableBorder := lipgloss.NormalBorder()
	if disableTableBorder {
		tableBorder = lipgloss.HiddenBorder()
	}

	t := table.New().
		Border(tableBorder).BorderRow(true).BorderRow(true).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("99"))).StyleFunc(func(row, col int) lipgloss.Style {
		if col > 0 {
			return lipgloss.NewStyle().Width(100).PaddingLeft(1)
		}
		return lipgloss.NewStyle().PaddingLeft(1)
	})

	t.Row("Title", advisory.DocumentTitle)
	t.Row("ID", advisory.DocumentTracking.Identification.ID)
	t.Row("Release Date", advisory.DocumentTracking.CurrentReleaseDate)
	t.Row("Link", fmt.Sprintf("https://fortiguard.fortinet.com/psirt/%s", advisory.DocumentTracking.Identification.ID))
	t.Row("CVSS Score", advisory.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3)

	affectedProductsListNeeded := false

	// print the document notes
	for _, note := range advisory.DocumentNotes.Note {

		// skip empty notes
		if regexp.MustCompile(`^\s*?(?:None)?\s*?$`).MatchString(note.Text) {
			// check the "Affected Products" document note because sometimes Fortinet doesn't fill this out :(
			if strings.Contains(note.Title, "Affected Products") {
				affectedProductsListNeeded = true
			}

			continue
		}

		noteText := strings.TrimSpace(note.Text)

		// apply post-processing to add in missing newlines so output looks better
		if strings.Contains(note.Title, "Affected Products") {
			noteText = regexp.MustCompile(`((At least)?\s*?Forti\w+ version [^\s]+(\s*?through \d+\.\d+\.\d+)?|Forti\w+ [^\s]+ all versions)\s?`).ReplaceAllString(noteText, "$0\n")
		}
		if strings.Contains(note.Title, "Solutions") {
			noteText = regexp.MustCompile(`((or above\s*?)Please)`).ReplaceAllString(noteText, "$2\nPlease")
		}

		t.Row(strings.TrimSpace(note.Title), noteText)
	}

	// List affected products if Fortinet didn't fill out the document note
	if affectedProductsListNeeded {
		for _, product := range advisory.ProductTree.Branch.Branch {
			t.Row("Product Type Affected", strings.TrimSpace(product.Name))

			affectedVersions := ""
			for _, version := range product.Branch {
				affectedVersions += fmt.Sprintf("%s\n", strings.TrimSpace(version.FullProductName.Text))
			}
			t.Row("Affected Versions", strings.TrimSpace(affectedVersions))
		}
	}

	fmt.Println(t)
	fmt.Println("")
}

var rootCmd = &cobra.Command{
	Use:   "cvrf-review",
	Short: "Review CVRF formmated vulnerability data",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	fortinetCmd.Flags().StringArrayVarP(&productTypes, "product-types", "p", []string{}, "Filter vulnerabilities by product type. Must match the value provided by Fortinet in the CVRF data. Examples: 'FortiOS', 'FortiClientEMS'")
	fortinetVersionCmd.Flags().StringVar(&productName, "product", "", "Product name to check (e.g., FortiOS)")
	fortinetVersionCmd.Flags().StringVarP(&productVersion, "version", "v", "", "Product version to check (e.g., 6.4.10)")

	// TODO: add date filtering
	fortinetCmd.AddCommand(fortinetVersionCmd)
	rootCmd.AddCommand(fortinetCmd)
	rootCmd.PersistentFlags().BoolP("help", "h", false, "Print usage")
	rootCmd.PersistentFlags().StringVarP(&severity, "severity", "s", "", "Filter vulnerabilities by severity (critical, high, medium, low)")
	rootCmd.PersistentFlags().Float64Var(&minCvssScore, "min-cvss-score", 0.0, "Filter vulnerabilities by a minimum CVSS score")
	rootCmd.PersistentFlags().Float64Var(&maxCvssScore, "max-cvss-score", 10.0, "Filter vulnerabilities by a maximum CVSS score")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Print output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&disableTableBorder, "disable-border", false, "Disable the table border")
	if help, _ := rootCmd.PersistentFlags().GetBool("help"); help {
		_ = rootCmd.Usage()
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalln(err)
	}
}
