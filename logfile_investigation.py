import json
import re
from collections import defaultdict, Counter
import time  # Import the time module

start_time = time.time()  # Start tracking time

# Define **suspicious file extensions** to flag as potentially malicious
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

# Open and parse JSON log file
#logfile_path = "webhoneypot-2025-05-31.json"
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

                # Track request method safely (this section should follow)
                method = entry.get("method", "UNKNOWN").strip().upper()
                ip_activity[sip]["request_methods"][method] += 1

            except json.JSONDecodeError:
                print(f"❌ Error: Failed to parse a log entry: {line.strip()[:100]}...")
                
except FileNotFoundError:
    print(f"❌ Error: The file '{logfile_path}' was not found. Please check the filename and try again.")
    exit()
            # Track events per IP
            method = entry.get("method", "UNKNOWN").strip().upper()

            # Force standardization of request methods
            standard_methods = {"GET", "POST", "CONNECT", "OPTIONS"}
            method = method.split()[0] if method.split()[0] in standard_methods else method

            ip_activity[sip]["request_methods"][method] += 1

            if "url" in entry:
                ip_activity[sip]["url_accesses"][entry["url"]] += 1

                # Check for suspicious file extensions in the URL
                for ext in suspicious_extensions:
                    if re.search(rf"\.{ext}\b", entry["url"], re.IGNORECASE):
                        ip_activity[sip]["file_requests"][entry["url"]] += 1

            if "time" in entry:
                ip_activity[sip]["timestamps"].append(entry["time"])
            if "useragent" in entry:
                for ua in entry["useragent"]:
                    user_agent_summary[ua] += 1

            if entry.get("response_id") and "status_code" in entry["response_id"]:
                ip_activity[sip]["response_codes"][str(entry["response_id"]["status_code"])] += 1

            # Credential Attempts
            for key, value in entry.items():
                if isinstance(value, str):
                    for username in default_usernames:
                        if re.search(rf"\b{username}\b", value, re.IGNORECASE):
                            credential_summary["Usernames"][username] += 1
                    for password in default_passwords:
                        if re.search(rf"\b{password}\b", value, re.IGNORECASE):
                            credential_summary["Passwords"][password] += 1

            # Hash detection
            entry_text = json.dumps(entry)
            for hash_type, pattern in hash_patterns.items():
                matches = re.findall(pattern, entry_text, re.IGNORECASE)
                if matches:
                    hash_summary[hash_type].update(matches)

        except json.JSONDecodeError:
            pass  
        except Exception as e:
            print(f"Unexpected error: {e}")

# Find top 10 most active IPs
top_ips = sorted(ip_activity.items(), key=lambda x: sum(len(v) for v in x[1].values()), reverse=True)[:10]

print("\n🔍 **Top 10 Most Active IP Addresses:**")

for sip, data in top_ips:
    total_events = sum(len(v) for v in data.values())
    print(f"- {sip}: {total_events} events detected")

# Find bottom 10 least active IPs   
bottom_ips = sorted(ip_activity.items(), key=lambda x: sum(sum(counter.values()) for counter in x[1].values() if isinstance(counter, Counter)))[:10]
                    
print("\n🔍 **Bottom 10 Least Active IP Addresses:**")

for sip, data in bottom_ips:
    total_events = sum(sum(counter.values()) for counter in data.values() if isinstance(counter, Counter))
    print(f"- {sip}: {total_events} events detected")
    
# Display total number of unique IPs (NEW ADDITION)
total_unique_ips = len(ip_activity)
print(f"\n🧮 **Total Unique IP Addresses:** {total_unique_ips}")

# Print general security event summary
print("\n🔍 **General Security Event Summary Across All IPs:**")

total_hashes = sum(sum(hash_counts.values()) for hash_counts in hash_summary.values())
total_credential_attempts = sum(credential_summary["Usernames"].values()) + sum(credential_summary["Passwords"].values())
total_requests = sum(sum(data["request_methods"].values()) for ip, data in ip_activity.items())

print(f"✔ Total requests: {total_requests}")
print(f"✔ Total detected hashes: {total_hashes}")
print(f"✔ Total credential attempts: {total_credential_attempts}")

# Print request methods summary
print("\n✔ **Request Methods Used:**")

method_summary = Counter()
for data in ip_activity.values():
    method_summary.update(data["request_methods"])

# Final cleanup—ensure only one "GET" entry appears
final_methods = Counter()
for method, count in method_summary.items():
    normalized_method = method.strip().upper()
    if normalized_method.startswith("GET"):
        normalized_method = "GET"  # Forces only one GET
    final_methods[normalized_method] += count

for method, count in final_methods.items():
    print(f"  {method}: {count} requests")

# Print top accessed URLs
print("\n✔ **Top Accessed URLs:**")

url_summary = Counter()
for ip, data in ip_activity.items():
    url_summary.update(data["url_accesses"])
for url, count in url_summary.most_common(10):
    print(f"  {url}: {count} accesses")

# Print flagged **Suspicious File Requests**
print("\n⚠ **Suspicious File Requests:**")

file_summary = Counter()
for ip, data in ip_activity.items():
    file_summary.update(data["file_requests"])
for file, count in file_summary.most_common(10):
    print(f"  {file}: {count} requests flagged as suspicious")

# Print top user-agent strings
print("\n🖥 **Top User-Agent Strings:**")

for ua, count in user_agent_summary.most_common(5):
    print(f"  - {ua}: {count} requests")

# Print summary of attempted credentials
print("\n✔ **Summary of Attempted Credentials:**")

print("\n🔑 **Top Attempted Usernames:**")

for username, count in credential_summary["Usernames"].most_common(10):
    print(f"  - {username}: {count} occurrences")

print("\n🔐 **Top Attempted Passwords:**")

for password, count in credential_summary["Passwords"].most_common(10):
    print(f"  - {password}: {count} occurrences")

# Print detected hashes with occurrence counts (Now labeled as "Hashes Detected")
if hash_summary:
    print("\n✔ **Hashes Detected:**")
    
    for hash_type, hash_counts in hash_summary.items():
        print(f"\n🔍 {hash_type} Hashes:")
        for hash_value, count in hash_counts.most_common():
            print(f"  - {hash_value}: {count} occurrences")

print("\n✅ **Log analysis complete!**")

end_time = time.time()
elapsed_time = end_time - start_time

# Convert to minutes and seconds
minutes = int(elapsed_time // 60)
seconds = int(elapsed_time % 60)

print(f"\n⏳ **Log analysis completed in {minutes} minutes and {seconds} seconds**")
