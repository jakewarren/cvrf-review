//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/jakewarren/cvrf-review/pkg/fortinet"
)

func parseCVRF(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{"error": "missing data"}
	}

	var c fortinet.CVRF
	if err := json.Unmarshal([]byte(args[0].String()), &c); err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	v := c.Vulnerability
	return map[string]interface{}{
		"document_title": c.DocumentTitle,
		"title":          v.Title,
		"cvss":           v.CVSSScoreSets.ScoreSetV3.BaseScoreV3,
		"cve":            v.CVE,
		"products":       v.ProductStatuses.Status.ProductID,
	}
}

func main() {
	js.Global().Set("parseCVRF", js.FuncOf(parseCVRF))
	<-make(chan struct{})
}
