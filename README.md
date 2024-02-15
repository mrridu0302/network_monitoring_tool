# network_monitoring_tool
The network monitoring tool revolutionises network monitoring with dynamic insights and instant alerts for proactive interventions. Automation simplifies network mapping, while advanced intrusion detection fortifies security. It aspires to be a cornerstone of reliability and efficiency in network management.

Enhance Real-time Monitoring
Optimise Traffic Analysis
Simplify Network Management
Strengthen Security Protocols

Algorithms Used:
- -
Packet Parsing Algorithm:
Extracts information from each captured packet, including Ethernet, IP, and TCP headers.
Source IP Tracking Algorithm:
Maintains a count of packets from each unique source IP.
Identifies potential security threats based on a predefined threshold.

Input:
- Captured packets from a network interface (Ethernet, IP, TCP headers).

Output:
- Displayed output in the console (or optionally stored in a file).
- Potential security threats based on the defined threshold.

Workflow:
1. Packet Capture:
- Utilises the pcap library to capture packets from a specified network
interface.
2. Packet Parsing:
- Extracts relevant information from each packet, including Ethernet, IP,
and TCP headers.
3. Source IP Tracking:
- Maintains a count of packets from each unique source IP.
- Updates the count for existing source IPs and adds new ones to the
tracking array.
4. Security Monitoring:
- Checks if the packet count from any source IP exceeds a predefined
threshold.
- If a threshold is crossed, potential security threats are identified.
