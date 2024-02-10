package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/jakewarren/cvrf-review/pkg/fortinet"
	"github.com/spf13/cobra"
)

// product types the user is interested in
var productTypes []string

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

// process the CVRF to determine if it matches any filters provided by the user. Returns true if the CVRF matches the filters and should be processed
func filterCVRF(advisory fortinet.CVRF) bool {
	// filter by severity
	cvssScore, _ := strconv.ParseFloat(advisory.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3, 64)

	// exclude vulnerablities with a CVSS score outside of the user defined range
	if cvssScore <= minCvssScore || cvssScore >= maxCvssScore {
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

	// TODO: add date filtering
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
