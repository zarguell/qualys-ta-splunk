[![CI](https://github.com/zarguell/qualys-ta-splunk/actions/workflows/download.yml/badge.svg)](https://github.com/zarguell/qualys-ta-splunk/actions/workflows/download.yml)

# Enhanced Qualys TA for Splunk

This is a simple modification to the Qualys TA for Splunk, created to change the default functionality to take "RESULTS" field data from the Qualys API, and "flatten" whitespace into a single space. While this functionality makes sense from a Splunk data parsing and conciseness perspective, it makes certain QIDs impossible to parse important information. For example, using this data will allow for separation of new line characters and tab characters to parse and separate multi-line and column results, such as "Installed Software Enumerated from Windows Installer".

This original intention was to use the [splunkbase_download](https://github.com/tfrederick74656/splunkbase-download) script to download the Splunk TA via Github Actions, add necessary code changes, for continious integrate of the small code change to the upstream Qualys TA from Splunkbase. Looks like SplunkBase authentication process changed a bit, so I took the [script](https://github.com/tfrederick74656/splunkbase-download/issues/1) from the issue on the repo, and modified it to work for Github Actions to download the latest Qualys TA release.

This explanation is sort of a stub, I intend to elaborate on the use cases in the future.

This is the simple modification made to the detectionpopulator.py script:

![Code Diff](assets/diff.png?raw=true "Cde Diff")

Qualys coded the TA to collapse on purpose, see the end of [this gist](https://gist.github.com/pmgupte/f9dd2d62c4861bfc852ef92137307515) describing why the new line characters caused concern for unexpected parsing on the Splunk side.