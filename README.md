# cvrf-review

[![Build Status](https://github.com/jakewarren/cvrf-review/workflows/lint/badge.svg)](https://github.com/jakewarren/cvrf-review/actions)
[![GitHub release](http://img.shields.io/github/release/jakewarren/cvrf-review.svg?style=flat-square)](https://github.com/jakewarren/cvrf-review/releases])
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/jakewarren/cvrf-review/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/jakewarren/cvrf-review)](https://goreportcard.com/report/github.com/jakewarren/cvrf-review)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](http://makeapullrequest.com)


A command line utility for parsing vendor bulletins in CVRF format. 

Currently there is only a Fortinet module that processes Fortinet's RSS feed for new advisories and allows for the user to filter by CVSS score and/or product types to display vulnerabilites of interest. 


## Install

```
go install github.com/jakewarren/cvrf-review@latest
```


## Usage

```
❯ cvrf-review fortinet -h
Get Fortinet vulnerabilities

Usage:
  cvrf-review fortinet [flags]

Flags:
  -p, --product-types stringArray   Filter vulnerabilities by product type. Must match the value provided by Fortinet in the CVRF data. Examples: 'FortiOS', 'FortiClientEMS'

Global Flags:
      --disable-border         Disable the table border
  -h, --help                   Print usage
      --json                   Print output in JSON format
      --max-cvss-score float   Filter vulnerabilities by a maximum CVSS score (default 10)
      --min-cvss-score float   Filter vulnerabilities by a minimum CVSS score
  -s, --severity string        Filter vulnerabilities by severity (critical, high, medium, low)
```

### Examples:

#### Get critical Fortinet vulnerabilities:
![screenshot](docs/images/fortinet_critical.png)

## Acknowledments
Inspired by [MaineK00n/vuls-data-update](https://github.com/MaineK00n/vuls-data-update).

