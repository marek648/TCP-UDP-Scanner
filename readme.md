# TCP/UDP Port Scanner

A simple TCP and UDP port scanner written in C++ that scans a specified IP address or domain name and reports the state of ports (open, filtered, or closed).

## Prerequisites

This tool is designed for Linux-based operating systems. Before running the scanner, you need to install the following dependencies:

### Install g++ compiler
```bash
sudo apt install g++
```

### Install libpcap development library
```bash
sudo apt-get install libpcap-dev
```

## Building the Project

Compile the program using make:
```bash
make
```

## Usage

Run the scanner with the following syntax:
```bash
./ipk-scan {-i <interface>} -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]
```

### Parameters

#### Optional Parameters
- `-i <interface>` - Specifies the network interface to use. If not provided, the first non-loopback interface will be automatically selected.

#### Required Parameters
- `<domain-name>` or `<IP-address>` - The target domain name or IP address to scan.

#### Port Specification (at least one required)
- `-pt <port-ranges>` - Port range(s) or individual ports to scan using TCP protocol.
- `-pu <port-ranges>` - Port range(s) or individual ports to scan using UDP protocol.

**Note:** You must specify at least one of `-pt` or `-pu`.

### Port Range Format

Port ranges can be specified as:
- Individual ports: `80`
- Multiple ports: `80,443,8080`
- Port ranges: `1-1024`
- Combination: `22,80-100,443`

## Examples

Scan TCP ports 1-1000 on example.com:
```bash
./ipk-scan -pt 1-1000 example.com
```

Scan UDP ports 53 and 161 on 192.168.1.1:
```bash
./ipk-scan -pu 53,161 192.168.1.1
```

Scan both TCP and UDP ports on a specific interface:
```bash
./ipk-scan -i eth0 -pt 80,443 -pu 53,67 example.com
```

## Output

The scanner reports the status of each scanned port:
- **Open** - Port is accepting connections
- **Closed** - Port is reachable but not accepting connections
- **Filtered** - Port status cannot be determined (likely blocked by firewall)

## Author

Marek Lörinc

## License

[Specify your license here]
