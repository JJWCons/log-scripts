import json
import re
from collections import defaultdict, Counter
import time

log_start_time = None
log_end_time = None
start_time = time.time()

suspicious_extensions = ["php", "exe", "zip", "rar", "tar", "gz", "bat", "sh", "py"]

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

def scan_for_credentials(obj, usernames_counter, passwords_counter):
    credential_patterns = [
        r"(user(name)?|login|auth)[=: ]+([^\s&\"',;]+)",
        r"(pass(word)?|pwd)[=: ]+([^\s&\"',;]+)"
    ]

    def recursive_scan(value):
        if isinstance(value, dict):
            for k, v in value.items():
                recursive_scan(k)
                recursive_scan(v)
        elif isinstance(value, list):
            for item in value:
                recursive_scan(item)
        elif isinstance(value, str):
            val = value.strip()
            for pattern in credential_patterns:
                matches = re.findall(pattern, val, re.IGNORECASE)
                for match in matches:
                    if "user" in match[0].lower() or "login" in match[0].lower():
                        usernames_counter[match[2]] += 1
                    elif "pass" in match[0].lower() or "pwd" in match[0].lower():
                        passwords_counter[match[2]] += 1
            if val in default_usernames:
                usernames_counter[val] += 1
            if val in default_passwords:
                passwords_counter[val] += 1

    recursive_scan(obj)

logfile_path = input("📂 Enter the log file name (e.g., webhoneypot-2025-05-31.json): ").strip()

try:
    with open(logfile_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())

                sip = entry.get("sip", "").strip()
                if not sip:
                    continue

                if "url" in entry:
                    url_str = entry["url"].lower()
                    match = re.search(
                        r"(username|user|login|email|account|pass|password|auth)=([\w\d!@#$%^&*()-_+]+)",
                        url_str, re.IGNORECASE
                    )
                    if match:
                        credential_type, credential_value = match.groups()
                        credential_summary[credential_type][credential_value] += 1

                if "method" in entry:
                    ip_activity[sip]["request_methods"][entry["method"].upper()] += 1

                if "url" in entry:
                    clean_url = entry["url"].strip()
                    ip_activity[sip]["url_accesses"][clean_url] += 1
                    for ext in suspicious_extensions:
                        if re.search(rf"\.{ext}\b", clean_url, re.IGNORECASE):
                            ip_activity[sip]["file_requests"][clean_url] += 1

                if "time" in entry:
                    ip_activity[sip]["timestamps"].append(entry["time"])
                    if log_start_time is None or entry["time"] < log_start_time:
                        log_start_time = entry["time"]
                    if log_end_time is None or entry["time"] > log_end_time:
                        log_end_time = entry["time"]

                if "useragent" in entry:
                    for ua in entry["useragent"]:
                        user_agent_summary[ua] += 1

                if entry.get("response_id") and "status_code" in entry["response_id"]:
                    ip_activity[sip]["response_codes"][str(entry["response_id"]["status_code"])] += 1

                scan_for_credentials(entry, credential_summary["Usernames"], credential_summary["Passwords"])

                entry_text = json.dumps(entry)
                for hash_type, pattern in hash_patterns.items():
                    matches = re.findall(pattern, entry_text, re.IGNORECASE)
                    if matches:
                        hash_summary[hash_type].update(matches)

            except json.JSONDecodeError:
                print(f"❌ Error: Failed to parse a log entry: {line.strip()[:100]}...")
            except Exception as e:
                print(f"❌ Unexpected error: {e}")

except FileNotFoundError:
    print(f"❌ Error: The file '{logfile_path}' was not found. Please check the filename and try again.")
    exit()

print("\n🕒 **Log Start Time:**", log_start_time if log_start_time else "❌ No start time detected")
print("🕒 **Log End Time:**", log_end_time if log_end_time else "❌ No end time detected")

total_unique_ips = len(ip_activity)
print(f"\n🧮 **Total Unique IP Addresses:** {total_unique_ips}")

top_ips = sorted(
    ip_activity.items(),
    key=lambda x: sum(sum(counter.values()) for counter in x[1].values() if isinstance(counter, Counter)),
    reverse=True
)[:10]

print("\n🔍 **Top 10 Most Active IP Addresses:**")
for sip, data in top_ips:
    total_events = sum(sum(counter.values()) for counter in data.values() if isinstance(counter, Counter))
    print(f"- {sip}: {total_events} events detected")

bottom_ips = sorted(
    ip_activity.items(),
    key=lambda x: sum(sum(counter.values()) for counter in x[1].values() if isinstance(counter, Counter))
)[:10]

print("\n🔍 **Bottom 10 Least Active IP Addresses:**")
if not bottom_ips:
    print("❌ No data available for least active IPs.")
else:
    for sip, data in bottom_ips:
        total_events = sum(sum(counter.values()) for counter in data.values() if isinstance(counter, Counter))
        print(f"- {sip}: {total_events} events detected")

print("\n---------------------------------\n")
print("✔ **Request Methods Used:**")

seen_methods = set()
method_summary = Counter()

for ip, data in ip_activity.items():
    for method, count in data["request_methods"].items():
        request_key = f"{ip}-{method}"
        if request_key not in seen_methods:
            method_summary[method] += count
            seen_methods.add(request_key)

if not method_summary:
    print("❌ No request methods detected in the logs.")
else:
    for method, count in sorted(method_summary.items(), key=lambda x: x[1], reverse=True):
        print(f"  {method}: {count} requests")

print("\n✔ **Top Accessed URLs:**")
url_summary = Counter()
for data in ip_activity.values():
    url_summary.update(data["url_accesses"])

if not url_summary:
    print("❌ No URLs detected in the logs.")
else:
    for url, count in url_summary.most_common(10):
        print(f"  {url}: {count} accesses")

print("\n **Suspicious File Requests:**")
file_summary = Counter()
for data in ip_activity.values():
    if "file_requests" in data:
        file_summary.update(data["file_requests"])

if not file_summary:
    print("❌ No suspicious file requests detected.")
else:
    for file, count in file_summary.most_common(10):
        print(f"  {file}: {count} flagged as suspicious")

print("\n✔ **Hashes Detected:**")
if not hash_summary:
    
print("\n✔ **Hashes Detected:**")
if not hash_summary:
    print("❌ No hashes detected in the log entries.")
else:
    for hash_type, hash_counts in hash_summary.items():
        if hash_counts:
            print(f"\n🔍 {hash_type} Hashes:")
            for hash_value, count in hash_counts.most_common():
                print(f"  {hash_value}: {count} occurrences")

print("\n🔐 **Credential Summary:**")
if not credential_summary["Usernames"] and not credential_summary["Passwords"]:
    print("❌ No credentials detected.")
else:
    print("\nUsernames:")
    for user, count in credential_summary["Usernames"].most_common(10):
        print(f"  {user}: {count} occurrences")

    print("\nPasswords:")
    for password, count in credential_summary["Passwords"].most_common(10):
        print(f"  {password}: {count} occurrences")

# Final timing output
end_time = time.time()
minutes, seconds = divmod(int(end_time - start_time), 60)
print(f"\n⏳ **Log analysis completed in {minutes} minutes and {seconds} seconds**")
