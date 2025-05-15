import json
from collections import Counter

# Storage for request counts per IP
ip_counts = Counter()

# Open and parse JSON log file line-by-line
with open("LOGFILE NAME") as f:
    for line in f:
        try:
            entry = json.loads(line.strip())  # Load JSON line-by-line

            # Extract source IP dynamically
            sip = entry.get("sip")
            if sip:
                ip_counts[sip] += 1

        except json.JSONDecodeError:
            pass  # Skip malformed JSON lines

# Print top 10 active IP addresses
print("\n🔍 **Top 10 Unique IPs by Total Requests:**")
for ip, count in ip_counts.most_common(10):
    print(f"{ip}: {count} requests")
