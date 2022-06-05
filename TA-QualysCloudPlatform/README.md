## Table of Contents

### OVERVIEW

- About the TA-QualysCloudPlatform
- Support and resources

### INSTALLATION AND CONFIGURATION

- Hardware and software requirements
- Installation steps
- Deploy to single server instance
- Configure TA-QualysCloudPlatform

### USER GUIDE

- Data types
- Lookups

---
### OVERVIEW

#### About the TA-QualysCloudPlatform

| Author | Qualys, Inc. |
| --- | --- |
| App Version | 1.10.3 |
| Vendor Products | Qualys |
| Has index-time operations | false |
| Create an index | false |
| Implements summarization | false |

The TA-QualysCloudPlatform allows a Splunk® Enterprise administrator to fetch the Vulnerability data from their Qualys subscription and index it. Administrator then can either analyze this data with other data sources using Splunk Enterprise Security App or use Qualys provided Apps for Splunk Enterprise to analyze Qualys specific data.

##### Scripts and binaries

This TA implements modular input. All the scripts reside in the bin directory.

#### Release Notes

##### New Features

- Docker image vulnerabilities feed from Container Security.
- Container Security data is in JSON format.

##### Enhancements
- None

##### Fixes
- None

##### Third-party software attributions

Version 1.10.3 of the TA-QualysCloudPlatform uses following third-party software or libraries.
- croniter-0.3.8-py2.7.egg and its dependencies listed below.
- python_dateutil-2.4.2-py2.7.egg
- six-1.9.0-py2.7.egg


##### Support and resources

**Support**

For documentation please see: https://community.qualys.com/docs/DOC-4876
In case any assistance is needed, please visit: https://www.qualys.com/forms/contact-support/


## INSTALLATION AND CONFIGURATION

#### Splunk Enterprise system requirements

Because this add-on runs on Splunk Enterprise, all of the [Splunk Enterprise system requirements](http://docs.splunk.com/Documentation/Splunk/latest/Installation/Systemrequirements) apply.

#### Download

Download the TA-QualysCloudPlatform from Splunkbase.

#### Installation steps

To install and configure this app on your supported platform, follow these steps:

1. Extract the downloaded zip tar ball.
2. Go to Splunk interface.
3. Login as admin.
4. Apps dropdown (top header on left) > Manage Apps.
5. Install app from file.
6. In "Upload an App" window, click "Choose File" button
7. Browse the tarball and click "Upload" button.


#### Configure TA-QualysCloudPlatform

TA-QualysCloudPlatform needs to be configured with Qualys credentials. The configuration is same as that of old Qualys App for Splunk Enterprise.

1. Go to Apps > Manage Apps.
2. Find TA-QualysCloudPlatform and click Set up.
3. Provide your Qualys username, password and API server in appropriate input boxes.
4. Make selection between different options provided.
5. Save.
6. Go to Settings > Data Inputs > TA-QualysCloudPlatform.
7. click New button.
8. Enter asked inputs, and click Next.
9. Again go to Settings > Data Inputs > TA-QualysCloudPlatform, and enable the input(s).

## USER GUIDE

### Data types

This app provides the index-time and search-time knowledge for the following types of data from Qualys:

** Host Detection **

This denotes a vulnerability detection on given host.

Sourcetype qualys:hostDetection is related to each such detection.

** WAS Finding **

This denotes a vulnerability detection in given web application.

Sourcetype qualys:wasFindings is related to each such detection.


These data types support the following Common Information Model data models:

- Vulnerability

** Policy Compliance Posture Info **

This denotes a compliance posture for given control on given host.

Sourcetype qualys:pc:postureInfo is related to each such event.

** Container Security Image Vulnerabilities **

This denotes a vulnerability detection on given docker image. 

Sourcetype qualys:cs:csImageVulnInfo is related to each such event.

### Lookups

The TA-QualysCloudPlatform contains 2 lookup files.

** qualys_kb**

This lookup contains the Qualys Knowledgebase.

- File location: TA-QualysCloudPlatform/lookups/qualys_kb.csv
- Lookup fields: QID,SEVERITY,VULN_TYPE,PATCHABLE,PCI_FLAG,TITLE,CATEGORY,PUBLISHED_DATETIME,CVSS_BASE,CVSS_TEMPORAL,CVE,VENDOR_REFERENCE

** qualys_severity**

This lookup contains mapping between numeric and verbal severity values.

- File location: TA-QualysCloudPlatform/lookups/qualys_severity.csv
- Lookup fields: severity_id,vendor_severity,severity
