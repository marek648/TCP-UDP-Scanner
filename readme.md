# TCP/UDP Port Scanner

A simple yet powerful TCP and UDP port scanner written in C++ that scans specified IP addresses or domain names and reports the state of ports (open, closed, or filtered). The scanner uses raw sockets for TCP SYN scanning and ICMP responses for UDP scanning.

## Features

- **TCP SYN Scanning**: Performs stealth SYN scans to detect open TCP ports
- **UDP Scanning**: Uses ICMP responses to detect closed UDP ports
- **IPv4 and IPv6 Support**: Automatically detects and handles both IP versions
- **Flexible Port Specification**: Supports individual ports, comma-separated lists, and ranges
- **Interface Selection**: Automatically selects appropriate network interface or allows manual specification
- **Domain Name Resolution**: Accepts both IP addresses and domain names as targets

## Prerequisites

This tool is designed for **Linux-based operating systems** and requires root privileges to create raw sockets.

### Required Dependencies

Install the g++ compiler:
```bash
sudo apt install g++
```

Install libpcap development library:
```bash
sudo apt-get install libpcap-dev
```

## Building the Project

Compile the program using make:
```bash
make
```

## Usage

**Important: This scanner must be run with root privileges (sudo) because it uses raw sockets.**

```bash
sudo ./ipk-scan [-i <interface>] [-pt <port-ranges>] [-pu <port-ranges>] <target>
```

### Parameters

#### Optional Parameters
- `-i <interface>` - Specifies the network interface to use (e.g., eth0, wlan0)
  - If not provided, automatically selects the first non-loopback interface
  - For localhost scanning, automatically uses "lo" interface

#### Required Parameters
- `<target>` - The target to scan (must be the last argument)
  - Can be a domain name (e.g., `example.com`)
  - Can be an IPv4 address (e.g., `192.168.1.1`)
  - Can be an IPv6 address (e.g., `2001:db8::1`)

#### Port Specification (at least one required)
- `-pt <port-ranges>` - TCP port(s) to scan
- `-pu <port-ranges>` - UDP port(s) to scan

**Note:** You must specify at least one of `-pt` or `-pu`.

### Port Range Format

Port ranges can be specified as:
- **Individual port**: `80`
- **Multiple ports**: `80,443,8080` (comma-separated, no spaces)
- **Port range**: `1-1024` (inclusive range with hyphen)
- **Note**: You cannot combine ranges and individual ports in the same argument

Valid port numbers are **1-65535**.

## Examples

Scan TCP ports 1-1000 on example.com:
```bash
sudo ./ipk-scan -pt 1-1000 example.com
```

Scan specific UDP ports on an IPv4 address:
```bash
sudo ./ipk-scan -pu 53,161,162 192.168.1.1
```

Scan both TCP and UDP ports:
```bash
sudo ./ipk-scan -pt 80,443,8080 -pu 53,67 example.com
```

Scan using a specific network interface:
```bash
sudo ./ipk-scan -i eth0 -pt 20-25 192.168.1.100
```

Scan localhost:
```bash
sudo ./ipk-scan -pt 22,80,443 127.0.0.1
```

Scan IPv6 address:
```bash
sudo ./ipk-scan -pt 80,443 -pu 53 2001:db8::1
```

## Output Format

The scanner displays results in the following format:

```
Interesting ports on example.com (93.184.216.34):
PORT     STATE
80/tcp   open
443/tcp  open
8080/tcp closed
22/tcp   filtered
53/udp   open
161/udp  closed
```

### Port States

**For TCP ports:**
- **open** - Port is accepting connections (received SYN-ACK response)
- **closed** - Port is reachable but not accepting connections (received RST-ACK response)
- **filtered** - No response received (likely blocked by firewall)

**For UDP ports:**
- **open** - No ICMP "port unreachable" response received within timeout period
- **closed** - Received ICMP Type 3 Code 3 (IPv4) or ICMPv6 Type 1 Code 4 (IPv6) response

## How It Works

### TCP Scanning
The scanner performs TCP SYN scanning (also known as "half-open" scanning):
1. Sends a TCP SYN packet to the target port
2. Waits for a response (with 1-second timeout and one retry)
3. Analyzes the TCP flags in the response to determine port state

### UDP Scanning
UDP scanning works by detecting ICMP error messages:
1. Sends a UDP packet to the target port
2. Waits for an ICMP "port unreachable" message
3. If no ICMP error is received, the port is considered open or filtered

## Technical Details

- Uses **raw sockets** (requires root privileges)
- Implements **libpcap** for packet capture and filtering
- Supports both **IPv4** and **IPv6** protocols
- Uses **1-second timeout** with **one automatic retry** for unresponsive ports
- Automatically calculates **checksums** for IP, TCP, and UDP headers
- Implements proper **packet filtering** to capture only relevant responses

## Limitations

- Requires root/sudo privileges
- UDP scanning cannot distinguish between "open" and "filtered" ports
- Scanning speed is limited by the 1-second timeout per port
- Some firewalls may rate-limit or block scanning attempts
- IPv6 link-local addresses may require interface specification

## Error Handling

The scanner validates:
- Port numbers (must be 1-65535)
- Port range order (start must be less than end)
- Network interface availability
- Domain name resolution
- Required arguments presence

## Author

Marek Lörinc

## Legal Notice

This tool is intended for network administration and security testing purposes only. Always ensure you have permission to scan the target systems. Unauthorized port scanning may be illegal in your jurisdiction.

## License

[Specify your license here]
