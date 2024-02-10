package fortinet

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"
)

const (
	rssURL      = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
	cvrfDataURL = "https://www.fortiguard.com/psirt/cvrf/%s"
)

// getRssEntries returns the RSS entries from the Fortinet RSS feed
func getRssEntries() (RSS, error) {
	resp, err := http.Get(rssURL)
	if err != nil {
		return RSS{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return RSS{}, errors.New("status is not ok. got response code: " + resp.Status)
	}

	defer resp.Body.Close()

	var rss RSS
	if err = xml.NewDecoder(resp.Body).Decode(&rss); err != nil {
		return RSS{}, err
	}

	return rss, nil
}

// getCVRFData fetches the CVRF data for a given advisory ID
func getCVRFData(advisoryID string) (CVRF, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	cvrfURL := fmt.Sprintf(cvrfDataURL, advisoryID)
	req, err := http.NewRequest("GET", cvrfURL, nil)
	if err != nil {
		return CVRF{}, err
	}
	req.Header.Set("User-Agent", "github.com/jakewarren/cvrf-review")

	resp, err := client.Do(req)
	if err != nil {
		return CVRF{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CVRF{}, errors.New("status is not ok. got response code: " + resp.Status)
	}

	var cvrf CVRF
	if err = xml.NewDecoder(resp.Body).Decode(&cvrf); err != nil {
		return CVRF{}, err
	}
	return cvrf, nil
}

func GetAdvisories() ([]CVRF, error) {
	var advisories []CVRF

	// get the vulnerabilities from the RSS feed
	entries, err := getRssEntries()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries.Channel.Item {
		u, urlParseErr := url.Parse(entry.Link)
		if urlParseErr != nil {
			return nil, fmt.Errorf("error parsing URL: %s", urlParseErr)
		}
		advisoryID := path.Base(u.Path)

		// get the CVRF data for each vulnerability
		cvrf, err := getCVRFData(advisoryID)
		if err != nil {
			fmt.Printf("error getting CVRF data for %s: %s\n", entry.Link, err)
			return nil, err
		}
		// append the advisory to the list
		advisories = append(advisories, cvrf)

		// sleep for a bit to avoid hitting any rate limit
		time.Sleep(1 * time.Second)
	}

	return advisories, nil
}
