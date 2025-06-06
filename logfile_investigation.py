import json
import re
from collections import defaultdict, Counter
import time

log_start_time = None
log_end_time = None
start_time = time.time()

# Define suspicious file extensions to flag as potentially malicious
suspicious_extensions = ["php", "exe", "zip", "rar", "tar", "gz", "bat", "sh", "py"]

# Define regex patterns for common hash formats
hash_patterns = {
    "MD5": r"\b[a-f0-9]{32}\b",
    "SHA1": r"\b[a-f0-9]{40}\b",
    "SHA256": r"\b[a-f0-9]{64}\b",
    "SHA512": r"\b[a-f0-9]{128}\b",
    "RIPEMD-160": r"\b[a-f0-9]{40}\b",
    "Whirlpool": r"\b[a-f0-9]{128}\b",
    "CRC32": r"\b(?!\d{8}\b)[a-fA-F0-9]{8}\b",
    "NTLM": r"\b[a-fA-F0-9]{32}\b",
    "bcrypt": r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}"
}

# Define commonly used usernames & passwords
default_usernames = {
    "admin", "root", "user", "test", "guest", "support", "sysadmin", "operator",
    "developer", "administrator", "superuser", "service", "manager", "backup",
    "security", "monitor", "demo", "default", "server", "data"
}

default_passwords = {
    "admin", "123456", "password", "qwerty", "12345", "letmein", "welcome", "password1",
    "admin123", "changeme", "12345678", "123456789", "1234", "1q2w3e4r", "sunshine",
    "monkey", "dragon", "football", "iloveyou", "123123"
}

# Storage for security event summaries
ip_activity = defaultdict(lambda: {
    "request_methods": Counter(),
    "url_accesses": Counter(),
    "timestamps": [],
    "user_agents": Counter(),
    "response_codes": Counter(),
    "file_requests": Counter(),
    "credential_attempts": Counter(),
    "detected_hashes": defaultdict(list)
})

hash_summary = defaultdict(Counter)
credential_summary = {"Usernames": Counter(), "Passwords": Counter()}
user_agent_summary = Counter()

#`extract_text`
def extract_text(value):
    if isinstance(value, str):
        return [value.strip()]  # Removes extra spaces
    elif isinstance(value, list):
        return [str(v).strip() for v in value]  # Converts list entries
    elif isinstance(value, dict):
        return [str(v).strip() for v in value.values()]  # Extracts dictionary values
    return []
    
# Open and parse JSON log file
logfile_path = input("📂 Enter the log file name (e.g., webhoneypot-2025-05-31.json): ").strip()

# Check if the file exists before opening it
try:
    with open(logfile_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())

                sip = entry.get("sip", "").strip()
                if not sip:
                    continue
                    
                # ✅ Debugging print to examine the full structure of each log entry
                print(f"📜 Full Log Entry: {entry}")  

                # ✅ Debugging print to check the 'data' field specifically
                if "data" in entry:
                    print(f"🔍 Inspecting 'data' field: {entry['data']}")  # Check if credentials exist there

                # ✅ Now proceed with extracting credentials 
                
                if "url" in entry:
                    #print(f"Found URL: {entry['url']}")  # Debugging statement

                    # Ensure URL tracking works
                    if entry["url"].strip():
                        ip_activity[sip]["url_accesses"][entry["url"].strip()] += 1
                else:
                    print("❌ No URL field in this entry.")  # Debugging statement
                    
                # Track request methods
                method = entry.get("method", "UNKNOWN").strip().upper()
                standard_methods = {"GET", "POST", "CONNECT", "OPTIONS", "HEAD"}
                method = method.split()[0] if method in standard_methods else "OTHER"

                # Ensure request method counting is correct
                ip_activity[sip]["request_methods"][method] += 1
                #print(f"Tracking method: {method} for IP {sip}") # for debugging duplicate GET requests
                
                # Track URLs & suspicious file requests
                if "url" in entry:
                    ip_activity[sip]["url_accesses"][entry["url"]] += 1
                    for ext in suspicious_extensions:
                        if re.search(rf"\.{ext}\b", entry["url"], re.IGNORECASE):
                            if "file_requests" not in ip_activity[sip]:  #  Ensure key exists
                                ip_activity[sip]["file_requests"] = Counter()  #  Initialize tracking
                            ip_activity[sip]["file_requests"][entry["url"]] += 1  #  Track suspicious files
                            
                if "time" in entry:
                    ip_activity[sip]["timestamps"].append(entry["time"])
                # Update log start and end times
                if log_start_time is None or entry["time"] < log_start_time:
                    log_start_time = entry["time"]
                if log_end_time is None or entry["time"] > log_end_time:
                    log_end_time = entry["time"]

                if "useragent" in entry:
                    for ua in entry["useragent"]:
                        user_agent_summary[ua] += 1

                if entry.get("response_id") and "status_code" in entry["response_id"]:
                    ip_activity[sip]["response_codes"][str(entry["response_id"]["status_code"])] += 1
                    
                def extract_text(value):
                    if isinstance(value, str):
                        return [value]
                    elif isinstance(value, list):
                        return [str(v) for v in value]
                    elif isinstance(value, dict):
                        return [str(v) for v in value.values()]
                    return []                 # Credential Attempts Tracking
                    
                # ✅ Step #1: Check if credential-related fields exist in the entry
                for key in entry.keys():
                    if key.lower() in {"username", "user", "login", "auth", "password", "pass"}:
                        print(f"✅ Found credential field: {key} -> {entry[key]}")  # Debugging print

                # ✅ Step #2: Extract and store credentials
                for key, value in entry.items():
                    extracted_values = extract_text(value)  # ✅ Use refined extraction function

                for text_value in extracted_values:
                    if key.lower() in {"username", "user", "login", "auth"}:
                        credential_summary["Usernames"][text_value] += 1
                    if key.lower() in {"password", "pass", "auth"}:
                        credential_summary["Passwords"][text_value] += 1

                # ✅ Continue with credential extraction
                for key, value in entry.items():
                    if isinstance(value, (str, list, dict)):  # Allow more formats
        
                         # Expand search to look for predefined usernames
                        if key.lower() in {"username", "user", "login", "auth"}:
                            for username in default_usernames:
                                if re.search(rf"\b{username}\b", value, re.IGNORECASE):
                                    credential_summary["Usernames"][username] += 1
                                    
                        # Expand search to look for predefined passwords
                        if key.lower() in {"password", "pass", "auth"}:
                            for password in default_passwords:
                                if re.search(rf"\b{password}\b", value, re.IGNORECASE):
                                    credential_summary["Passwords"][password] += 1
        
                        # Capture any username outside predefined list
                        if key.lower() in {"username", "user", "login", "auth"}:
                            detected_username = value.strip()
                            if detected_username and detected_username not in default_usernames:
                                credential_summary["Usernames"][detected_username] += 1  # Track unknown usernames

                        # Capture any password outside predefined list
                        if key.lower() in {"password", "pass", "auth"}:
                            detected_password = value.strip()
                            if detected_password and detected_password not in default_passwords:
                                credential_summary["Passwords"][detected_password] += 1  # Track unknown passwords
                # Hash detection
                entry_text = json.dumps(entry)
                for hash_type, pattern in hash_patterns.items():
                    matches = re.findall(pattern, entry_text, re.IGNORECASE)
                    if matches:
                        hash_summary[hash_type].update(matches)

            except json.JSONDecodeError:
                print(f"❌ Error: Failed to parse a log entry: {line.strip()[:100]}...")

except FileNotFoundError:
    print(f"❌ Error: The file '{logfile_path}' was not found. Please check the filename and try again.")
    exit()

# Print request methods, suspicious files, and other summaries below
# Display Timestamps 
print("\n🕒 **Log Start Time:**", log_start_time if log_start_time else "❌ No start time detected")
print("🕒 **Log End Time:**", log_end_time if log_end_time else "❌ No end time detected")
        
# Display total number of unique IPs
total_unique_ips = len(ip_activity)
print(f"\n🧮 **Total Unique IP Addresses:** {total_unique_ips}")

# Find top 10 most active IPs
top_ips = sorted(ip_activity.items(), key=lambda x: sum(sum(counter.values()) for counter in x[1].values() if isinstance(counter, Counter)), reverse=True)[:10]
print("\n🔍 **Top 10 Most Active IP Addresses:**")
for sip, data in top_ips:
    total_events = sum(sum(counter.values()) for counter in data.values() if isinstance(counter, Counter))
    print(f"- {sip}: {total_events} events detected")

# Find bottom 10 least active IPs
bottom_ips = sorted(ip_activity.items(), key=lambda x: sum(sum(counter.values()) for counter in x[1].values() if isinstance(counter, Counter)))[:10]

print("\n🔍 **Bottom 10 Least Active IP Addresses:**")  # No extra newline

if not bottom_ips:
    print("❌ No data available for least active IPs.")
else:
    for sip, data in bottom_ips:
        total_events = sum(sum(counter.values()) for counter in data.values() if isinstance(counter, Counter))
        print(f"- {sip}: {total_events} events detected")  # No extra newline here

# Add a **single clean space** before request methods
print("\n---------------------------------\n")  # Creates a clear separation
print("✔ **Request Methods Used:**")  # No extra newline
# Print request methods summary

seen_methods = set()
method_summary = Counter()

for ip, data in ip_activity.items():
    for method, count in data["request_methods"].items():
        request_key = f"{ip}-{method}"
        if request_key not in seen_methods:
            method_summary[method] += count
            seen_methods.add(request_key)
            
# If no request methods are detected, print a message
if not method_summary:
    print("\n✔ **Request Methods Used:**\n")  # Add extra newline

# If no request methods are detected, print a message
if not method_summary:
    print("❌ No request methods detected in the logs.")
else:
    for method, count in sorted(method_summary.items(), key=lambda x: x[1], reverse=True):
        print(f"  {method}: {count} requests")  # No extra newline after each request
        
# Print top accessed URLs
print("\n✔ **Top Accessed URLs:**")
url_summary = Counter()
for data in ip_activity.values():
    url_summary.update(data["url_accesses"])

if not url_summary:
    print("❌ No URLs detected in the logs.")
else:
    for url, count in url_summary.most_common(10):
        print(f"  {url}: {count} accesses")

# Print suspicious file requests
print("\n **Suspicious File Requests:**")

file_summary = Counter()
for data in ip_activity.values():
    if "file_requests" in data:
        file_summary.update(data["file_requests"])

if not file_summary:
    print("❌ No suspicious file requests detected.")
else:
    for file, count in file_summary.most_common(10):  # Show top 10 suspicious files
        print(f"  {file}: {count} flagged as suspicious")  # No extra "\n" here
        
# Print detected hashes or indicate none found
print("\n✔ **Hashes Detected:**")
if not hash_summary:
    print("❌ No hashes detected in the log entries.")
else:
    for hash_type, hash_counts in hash_summary.items():
        if hash_counts:
            print(f"\n🔍 {hash_type} Hashes:")
            for hash_value, count in hash_counts.most_common():
                print(f"  {hash_value}: {count} occurrences")

# Debugging: Check if credentials exist before printing
print("\n🔍 Credential Debug Info:")
print("Usernames:", credential_summary["Usernames"])
print("Passwords:", credential_summary["Passwords"])

# Print summary of attempted credentials
print("\n🔐 **Credential Summary:**")

if not credential_summary["Usernames"] and not credential_summary["Passwords"]:
    print("❌ No credentials detected.")
else:
    print("\nUsernames:")
    for user, count in credential_summary["Usernames"].items():  # Use `.items()`, not `.most_common()`
        print(f"  {user}: {count} occurrences")

    print("\nPasswords:")
    for password, count in credential_summary["Passwords"].items():
        print(f"  {password}: {count} occurrences")

# Print processing time
end_time = time.time()
minutes, seconds = divmod(int(end_time - start_time), 60)
print(f"\n⏳ **Log analysis completed in {minutes} minutes and {seconds} seconds**")
