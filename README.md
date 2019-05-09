# Polarity RiskIQ SIS Integration

> Due to the time it can take for lookups against certain indicators, we recommend that this integration be run in "On Demand Only" mode.

As attacks against the organization increase, it’s more important than ever to have a security program built on robust and reliable data to enrich analysis and inform the decision-making process. RiskIQ offers the ability to ingest critical security data programmatically at scale.

The Polarity RiskIQ integration allows Polarity to search RiskIQ Security Intelligence Services (SIS API) to return threat information on IP's, Domains and URL's.

More information on RiskIQ SIS please see https://www.riskiq.com/products/security-intelligence-services

For information about the RiskIQ API please see https://api.riskiq.net/api/concepts.html

![riskiq](https://user-images.githubusercontent.com/22529325/55735171-d4df4000-59ee-11e9-93ff-43fe541c593f.gif)

## RiskIQ Integration Options

### RiskIQ Host
The host to use for the RiskIQ SIS API

### RiskIQ API Key

RiskIQ Security Intelligence Services API Key

### RiskIQ Private Key

RiskIQ Security Intelligence Services Private Key

### Domain and IP Blacklist

This is an alternate option that can be used to specify domains or IPs that you do not want sent to RiskIQ.  The data must specify the entire IP or domain to be blocked (e.g., www.google.com is treated differently than google.com).

### Domain Blacklist Regex

This option allows you to specify a regex to blacklist domains.  Any domain matching the regex will not be looked up.  If the regex is left blank then no domains will be blacklisted.

### IP Blacklist Regex

This option allows you to specify a regex to blacklist IPv4 Addresses.  Any IPv4 matching the regex will not be looked up.  If the regex is left blank then no IPv4s will be blacklisted.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
