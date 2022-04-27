# Enhanced Qualys TA for Splunk

This is a simple modification to the Qualys TA for Splunk, created to change the default functionality to take "RESULTS" field data from the Qualys API, and "flatten" whitespace into a single space. While this functionality makes sense from a Splunk data parsing and conciseness perspective, it makes certain QIDs impossible to parse important information. For example, using this data will allow for separation of new line characters and tab characters to parse and separate multi-line and column results, such as "Installed Softwaree Enumerated from Windows Installer".

This repo uses the upstream [splunkbase_download](https://github.com/tfrederick74656/splunkbase-download) script to download the Splunk TA via Github Actions, add necessary code changes, for continious integrate of the small code change to the upstream Qualys TA from Splunkbase.

This explanation is sort of a stub, I intend to elaborate on the use cases in the future.