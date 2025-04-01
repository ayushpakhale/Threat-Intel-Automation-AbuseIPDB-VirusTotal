import requests
import pandas as pd
from pymongo import MongoClient
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import time
#requirements.txt has been created for installation

#Configuration (All API keys and URLS)
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/blacklist'
ABUSEIPDB_HEADERS = {
    'Accept': 'application/json',
    'Key': '97ba71295d77f2e8dd91fbbccb0423649d6fe0c84caf1e6dd489a4325cda1c94af5ecee3a277c864'
}

MONGO_URL = "mongodb+srv://ayushpakhale29:C4aNaY4hNhr62KZv@cluster0.r5b0mnv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME = "CyberSecurity"
COLLECTION_NAME = "AbuseVT"

VT_API_KEY = "31cdac3feb124fd3db13d46159ec762bb2e0afa09beca7decaf5c204bc8a1429"
VT_HEADERS = {"x-apikey": VT_API_KEY}

# Email Config
GMAIL_USER = "ayushpakhaledev@gmail.com"
GMAIL_PASSWORD = "rwwe wlxr rrva ciab"
#change the recipient of the mail if required here
RECIPIENT_EMAIL = "lokesh.kumawat@optiv.com"

def get_abuseipdb_data():
    print("Fetching AbuseIPDB blacklist...")
    response = requests.get( ABUSEIPDB_URL, headers=ABUSEIPDB_HEADERS, params={'confidenceMinimum': '97'})
    data = response.json()["data"]
    df = pd.DataFrame(data)
    excel_path = "abuseipdb_report.xlsx"
    df.to_excel(excel_path, index=False)
    print(f"IP data saved to {excel_path}")
    return df, excel_path

def store_in_mongodb(df):
    print("Connecting to MongoDB...")
    client = MongoClient(MONGO_URL)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    
    data_to_insert = df.to_dict(orient="records")
    collection.insert_many(data_to_insert)
    print(f"Inserted {len(data_to_insert)} records into MongoDB")

def analyze_with_virustotal(df):
    print("Starting VirusTotal analysis...")
    client = MongoClient(MONGO_URL)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    vt_results = []

    # we are only doing 5 IP's because vt only allows 500 Lookups for free account and we are receiving more han 10000 IP's from AbuseIPDB
    #head can be increased to get more ips

    
    for index, row in df.head(5).iterrows():  # Process first 5 IPs 
        ip = row["ipAddress"]
        print(f"Processing IP: {ip}")
        
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=VT_HEADERS
            )
            response.raise_for_status()
            vt_data = response.json()

            # Store in MongoDB
            collection.update_one(
                {"ipAddress": ip},
                {"$set": {"virustotal": vt_data}},
                upsert=True
            )
            
            # initializaion for email report for presentable format
            stats = vt_data['data']['attributes']['last_analysis_stats']
            result = {
                "IP": ip,
                "Country": vt_data['data']['attributes'].get('country', 'Unknown'),
                "Reputation": vt_data['data']['attributes'].get('reputation', 0),
                "Malicious": stats['malicious'],
                "Suspicious": stats['suspicious'],
                "Harmless": stats['harmless'],
                "Undetected": stats['undetected'],
                "Tags": ", ".join(vt_data['data']['attributes'].get('tags', []))
            }
            vt_results.append(result)
            
            print(f"Updated VirusTotal data for {ip}")
            
        except Exception as e:
            print(f"Error processing {ip}: {str(e)}")
            vt_results.append({
                "IP": ip,
                "Error": str(e)
            })
        
        time.sleep(15)  # Rate limiting
    
    # VT Excel Report
    vt_df = pd.DataFrame(vt_results)
    vt_excel_path = "virustotal_report.xlsx"
    vt_df.to_excel(vt_excel_path, index=False)
    print(f"VirusTotal data saved to {vt_excel_path}")
    
    return vt_results, vt_excel_path

def generate_html_table(vt_data):
    #Table generation
    table_rows = ""
    for item in vt_data:
        if "Error" in item:
            table_rows += f"""
            <tr style="background-color: #fff3e0;">
                <td>{item['IP']}</td>
                <td colspan="4" style="color: red;">{item['Error']}</td>
            </tr>
            """
        else:
            risk_color = "red" if item["Malicious"] > 0 else "green"
            table_rows += f"""
            <tr>
                <td>{item['IP']}</td>
                <td>{item['Country']}</td>
                <td style='color: {risk_color}; font-weight: bold'>{item['Malicious']}</td>
                <td>{item['Suspicious']}</td>
                <td>{item['Reputation']}</td>
            </tr>
            """
    
    return f"""
    <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%;">
        <thead>
            <tr style="background-color: #0047AB; color: white;">
                <th>IP Address</th>
                <th>Country</th>
                <th>Malicious</th>
                <th>Suspicious</th>
                <th>Reputation</th>
            </tr>
        </thead>
        <tbody>
            {table_rows}
        </tbody>
    </table>
    """

def send_email(abuse_excel_path, vt_excel_path, vt_results):
    print("Preparing email...")
    
    msg = MIMEMultipart()
    msg['From'] = GMAIL_USER
    msg['To'] = RECIPIENT_EMAIL
    msg['Subject'] = "Threat Intelligence Report for Optiv SOAR Position"
    
    # HTML Email Body & Table
    html = f"""
    <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #0047AB;">Threat Intelligence Report</h2>
            <p>Attached files:</p>
            <ul>
                <li><b>abuseipdb_report.xlsx</b>: Raw data from AbuseIPDB</li>
                <li><b>virustotal_report.xlsx</b>: Detailed VirusTotal analysis</li>
            </ul>
            
            <h3>VirusTotal Summary</h3>
            {generate_html_table(vt_results)}
            
            <p style="margin-top: 20px; font-size: 0.9em; color: #666;">
                Report generated on {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')} By Ayush
            </p>
        </body>
    </html>
    """
    msg.attach(MIMEText(html, 'html'))
    
    # Attaching Excel files
    for filepath in [abuse_excel_path, vt_excel_path]:
        with open(filepath, "rb") as f:
            part = MIMEApplication(f.read(), Name=filepath)
            part['Content-Disposition'] = f'attachment; filename="{filepath}"'
            msg.attach(part)
    
    # Send email
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_PASSWORD.replace(" ", ""))
            server.sendmail(GMAIL_USER, RECIPIENT_EMAIL, msg.as_string())
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")

def main():
    #int main
    try:
        #1 Get AbuseIPDB data
        abuse_df, abuse_excel_path = get_abuseipdb_data()
        
        #2 Store in MongoDB
        store_in_mongodb(abuse_df)
        
        #3 Enrich with VirusTotal
        vt_results, vt_excel_path = analyze_with_virustotal(abuse_df)
        
        #4 Send email with both reports
        send_email(abuse_excel_path, vt_excel_path, vt_results)
        
        print("Process completed successfully")
        input("\nAll done! Press Enter to close this window...")
    except Exception as e:
        print(f"error in main execution: {str(e)}")

if __name__ == "__main__":
    main()
    
