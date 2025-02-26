### **📌 How to Install & Run the Enhanced Automated Recon Script**  


#### **1️⃣ Install Dependencies**  
Before running the script, ensure all required tools are installed:  
```bash
sudo apt update && sudo apt install -y subfinder amass nmap nuclei curl jq whois gowitness
go install github.com/haccer/subjack@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/httprobe@latest
export PATH=$HOME/go/bin:$PATH
```

#### **2️⃣ Ensure Script is Up-to-Date**  
Make sure you have the latest version of the `recon.sh` script.


#### **2️⃣ Download & Save the Script**  
Create a file named `recon.sh` and paste the script inside it.

#### **3️⃣ Make the Script Executable**  
```bash
chmod +x recon.sh
```

#### **4️⃣ Run the Script**  
Execute the script by providing a target domain:  
```bash
./recon.sh example.com
```

#### **📌 Example Output**  
```
[+] Enumerating subdomains for example.com...
[+] Checking for subdomain takeovers...
[+] Scanning ports on live subdomains...
[+] Checking security headers...
[+] Performing DNS and WHOIS lookup...
[+] Capturing screenshots of live subdomains...
[+] Recon completed. Check output files.
```


#### **📌 Example Output**  
```
[+] Enumerating subdomains for example.com...
[+] Checking for subdomain takeovers...
[+] Scanning ports on live subdomains...
[+] Checking security headers...
[+] Performing DNS and WHOIS lookup...
[+] Capturing screenshots of live subdomains...
[+] Recon completed. Check output files.
```

#### **📂 Output Files Generated**  
- `subdomains.txt` → List of found subdomains  
- `takeover_results.txt` → Subdomain takeover results  
- `open_ports.txt` → Open ports from Naabu  
- `nmap_results.txt` → Detailed Nmap scan report  
- `screenshots/` → Screenshots of live subdomains  

🚀 **Now you're all set for automated recon!** Let me know if you need any tweaks. 😃
