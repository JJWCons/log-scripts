import json
import re
from collections import defaultdict, Counter
import time

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
    "attempted_usernames": Counter(),
    "attempted_passwords": Counter(),
    "detected_hashes": defaultdict(Counter)
})

# Prompt for log file and IPs
logfile_path = input("📂 Enter the log file name (e.g., webhoneypot-2025-05-31.json): ").strip()
target_ips = input("🔍 Enter a single IP address or multiple addresses separated by commas: ").strip().split(",")

# Load and process the log file
try:
    with open(logfile_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                sip = entry.get("sip", "").strip()
                if not sip:
                    continue

                ip_activity[sip]["request_methods"][entry.get("method", "UNKNOWN").upper()] += 1

                if "url" in entry:
                    ip_activity[sip]["url_accesses"][entry["url"]] += 1
                    for ext in suspicious_extensions:
                        if re.search(rf"\.{ext}\b", entry["url"], re.IGNORECASE):
                            ip_activity[sip]["file_requests"][entry["url"]] += 1

                if "time" in entry:
                    ip_activity[sip]["timestamps"].append(entry["time"])

                if "useragent" in entry:
                    for ua in entry["useragent"]:
                        ip_activity[sip]["user_agents"][ua] += 1

                if entry.get("response_id") and "status_code" in entry["response_id"]:
                    ip_activity[sip]["response_codes"][str(entry["response_id"]["status_code"])] += 1

                for key, value in entry.items():
                    if isinstance(value, str):
                        for username in default_usernames:
                            if re.search(rf"\b{username}\b", value, re.IGNORECASE):
                                ip_activity[sip]["attempted_usernames"][username] += 1
                        for password in default_passwords:
                            if re.search(rf"\b{password}\b", value, re.IGNORECASE):
                                ip_activity[sip]["attempted_passwords"][password] += 1

                entry_text = json.dumps(entry)
                for hash_type, pattern in hash_patterns.items():
                    matches = re.findall(pattern, entry_text, re.IGNORECASE)
                    if matches:
                        ip_activity[sip]["detected_hashes"][hash_type].update(matches)

            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"Unexpected error: {e}")
except FileNotFoundError:
    print(f"❌ Error: File '{logfile_path}' not found.")
    exit()

# Analyze each target IP
for target_ip in map(str.strip, target_ips):
    print(f"\n🔎 **Analysis for IP: {target_ip}**")

    if target_ip in ip_activity:
        timestamps = ip_activity[target_ip]["timestamps"]
        if timestamps:
            print(f"\n⏳ **Time Frame of Activity:** {min(timestamps)} → {max(timestamps)}")
        else:
            print("\n❌ No recorded timestamps for this IP.")

        if ip_activity[target_ip]["request_methods"]:
            print("\n✔ **Request Methods Used:**")
            for method, count in ip_activity[target_ip]["request_methods"].most_common():
                print(f"  {method}: {count} requests")
        else:
            print("\n❌ No request methods recorded for this IP.")

        if ip_activity[target_ip]["url_accesses"]:
            print("\n✔ **Top Accessed URLs:**")
            for url, count in ip_activity[target_ip]["url_accesses"].most_common(10):
                print(f"  {url}: {count} accesses")
        else:
            print("\n❌ No accessed URLs recorded for this IP.")

        if ip_activity[target_ip]["file_requests"]:
            print("\n⚠ **Suspicious File Requests:**")
            for file, count in ip_activity[target_ip]["file_requests"].most_common(10):
                print(f"  {file}: {count} requests flagged as suspicious")
        else:
            print("\n❌ No suspicious file requests recorded for this IP.")

        if ip_activity[target_ip]["response_codes"]:
            print("\n✔ **Response Codes:**")
            for code, count in ip_activity[target_ip]["response_codes"].most_common():
                print(f"  HTTP {code}: {count} occurrences")
        else:
            print("\n❌ No response codes recorded for this IP.")

        if ip_activity[target_ip]["user_agents"]:
            print("\n🖥 **User-Agent Strings:**")
            for ua, count in ip_activity[target_ip]["user_agents"].most_common(5):
                print(f"  - {ua}: {count} requests")
        else:
            print("\n❌ No user-agent strings recorded for this IP.")

        if ip_activity[target_ip]["attempted_usernames"]:
            print("\n🔑 **Attempted Usernames:**")
            for username, count in ip_activity[target_ip]["attempted_usernames"].most_common(5):
                print(f"  - {username}: {count} occurrences")
        else:
            print("\n❌ No attempted usernames recorded for this IP.")

        if ip_activity[target_ip]["attempted_passwords"]:
            print("\n🔐 **Attempted Passwords:**")
            for password, count in ip_activity[target_ip]["attempted_passwords"].most_common(5):
                print(f"  - {password}: {count} occurrences")
        else:
            print("\n❌ No attempted passwords recorded for this IP.")

        if ip_activity[target_ip]["detected_hashes"]:
            print("\n✔ **Hashes Detected:**")
            for hash_type, hash_counts in ip_activity[target_ip]["detected_hashes"].items():
                print(f"\n🔍 {hash_type} Hashes:")
                for hash_value, count in hash_counts.most_common():
                    print(f"  - {hash_value}: {count} occurrences")
        else:
            print("\n❌ No hashes detected for this IP.")
    else:
        print(f"\n❌ No data found for IP: {target_ip}")

# Final timing
end_time = time.time()
minutes, seconds = divmod(int(end_time - start_time), 60)
print(f"\n✅ Multi-IP Analysis Complete!")
print(f"⏳ Log analysis completed in {minutes} minutes and {seconds} seconds")
