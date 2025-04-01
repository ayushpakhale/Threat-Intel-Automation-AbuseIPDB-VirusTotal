# Threat-Intel-Automation-AbuseIPDB-VirusTotal
Threat-Intel-Automation is a fully automated end-to-end threat intelligence pipeline that integrates AbuseIPDB and VirusTotal for seamless IP reputation analysis and reporting. The script efficiently handles the entire workflow, from fetching malicious IPs to sending a well-structured email report—all with a single execution.

Key Features:
✅ Fetches Threat Data: Retrieves a list of suspicious IPs from AbuseIPDB and stores them in an Excel file
✅ Database Storage: Saves the extracted data into a MongoDB collection for further processing
✅ Threat Intelligence Enrichment: Queries VirusTotal API for in-depth threat analysis of the stored IPs
✅ Report Generation: Compiles a presentable email report in table format with attachments for easy review
✅ Automated Email Delivery: Sends an email with two attachments:
      > The original AbuseIPDB IP list
      > The VirusTotal-enriched report
✅ Fully Automated Execution: The entire process is hands-free—just run the script and wait for the results.
