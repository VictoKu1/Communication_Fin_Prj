# Network Security Lab: Packet Sniffing and Spoofing

## Overview

This repository contains a comprehensive network security laboratory focused on **packet sniffing** and **spoofing** techniques. The project is designed for educational purposes to help students understand fundamental network security concepts, attack vectors, and defensive mechanisms through hands-on experimentation.

## 🎯 Learning Objectives

- **Packet Sniffing**: Learn to capture and analyze network packets using both high-level (Scapy) and low-level (libpcap) approaches
- **Packet Spoofing**: Understand how to forge network packets with arbitrary source addresses
- **Network Security**: Gain practical experience with common network attacks and their detection
- **Programming Skills**: Develop proficiency in Python and C for network programming
- **Security Awareness**: Understand the importance of network monitoring and security controls


## 🛠️ Technologies Used

### Programming Languages
- **Python**: High-level packet manipulation using Scapy
- **C**: Low-level network programming with raw sockets and libpcap

### Key Libraries & Tools
- **Scapy**: Python library for packet manipulation
- **libpcap**: C library for packet capture
- **Docker**: Containerization for isolated lab environment
- **Wireshark**: Packet analysis and visualization

### Network Protocols
- **ICMP**: Internet Control Message Protocol
- **TCP**: Transmission Control Protocol
- **UDP**: User Datagram Protocol
- **ARP**: Address Resolution Protocol

## 🚀 Getting Started

### Prerequisites

- Docker and Docker Compose
- Python 3.x with Scapy (`pip install scapy`)
- C compiler (gcc) with development libraries
- libpcap development libraries

### Environment Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd Communication_Fin_Prj-master
   ```

2. **Start the lab environment**:
   ```bash
   cd Labsetup
   docker-compose up -d
   ```

3. **Access the containers**:
   ```bash
   # Attacker container
   docker exec -it seed-attacker bash
   
   # Host container
   docker exec -it host-10.9.0.5 bash
   ```

## 📋 Lab Tasks

### Task 1: Scapy-based Packet Manipulation

#### Task 1.1: Basic Packet Sniffing
- **File**: `Task 1.1/ICMPScapy.py`
- **Objective**: Capture ICMP packets using Scapy
- **Key Concepts**: Network interface selection, packet filtering

#### Task 1.1B: Advanced Filtering
- **Files**: 
  - `Task 1.1B/ICMP/ICMPScapy.py` - ICMP packet filtering
  - `Task 1.1B/TCP/TCPScapy.py` - TCP packet filtering
  - `Task 1.1B/Subnet/subnet Scapy.py` - Subnet-based filtering
- **Objective**: Implement Berkeley Packet Filter (BPF) expressions

#### Task 1.2: Packet Spoofing
- **File**: `Task 1.2/SpoofScapy.py`
- **Objective**: Forge ICMP packets with arbitrary source addresses
- **Key Concepts**: IP header manipulation, packet construction

#### Task 1.3: Traceroute Implementation
- **File**: `Task 1.3/traceroute.py`
- **Objective**: Create a simple traceroute using TTL manipulation
- **Key Concepts**: TTL field, ICMP error messages

#### Task 1.4: Combined Sniffing and Spoofing
- **Files**: 
  - `Task 1.4/SniffandSpoofLAN.py` - LAN-based implementation
  - `Task 1.4/SniffandSpoofOut.py` - External network implementation
- **Objective**: Respond to ping requests for non-existent hosts

### Task 2: C-based Network Programming

#### Task 2.1A: Basic Packet Sniffing in C
- **File**: `Task 2.1A/snif.c`
- **Objective**: Implement packet capture using libpcap
- **Key Concepts**: Raw socket programming, packet header parsing

#### Task 2.1B: Advanced C Sniffing
- **Files**:
  - `Task 2.1B/sniffICMP.c` - ICMP packet capture
  - `Task 2.1B/snifTCP.c` - TCP packet capture
- **Objective**: Implement protocol-specific packet filtering

#### Task 2.1C: Password Sniffing
- **File**: `Task 2.1C/sniffingPasswords.c`
- **Objective**: Capture Telnet credentials from network traffic
- **Key Concepts**: TCP payload extraction, credential harvesting

#### Task 2.2A: UDP Packet Spoofing
- **File**: `Task 2.2A/spoof.c`
- **Objective**: Forge UDP packets with arbitrary source addresses
- **Key Concepts**: Raw socket creation, packet header construction

#### Task 2.2B: ICMP Echo Spoofing
- **File**: `Task 2.2B/spoofIcmpEcho.c`
- **Objective**: Create spoofed ICMP echo requests
- **Key Concepts**: Checksum calculation, ICMP header manipulation

#### Task 2.3: Combined C Implementation
- **File**: `Task 2.3/sniffAndSpoofICMPEcho.c`
- **Objective**: Implement real-time packet sniffing and spoofing
- **Key Concepts**: Multi-threading, packet interception and modification

## 🔧 Building and Running

### Python Scripts
```bash
# Run Scapy scripts
cd Labsetup/volumes/Task_1.1
python3 ICMPScapy.py
```

### C Programs
```bash
# Build all C programs
cd Labsetup/volumes
make

# Build specific task
cd Task_2.1A
make

# Run compiled programs
./snif
```

## 📊 Packet Capture Files

The `PCAP/` directory contains packet capture files demonstrating various network scenarios:
- ICMP packet captures
- TCP connection monitoring
- Spoofed packet examples
- Combined sniffing and spoofing results

## 🔒 Security Considerations

⚠️ **Important**: This lab is designed for educational purposes in controlled environments only.

- **Legal Compliance**: Ensure you have permission to perform network testing
- **Isolated Environment**: Use the provided Docker containers to prevent interference with production networks
- **Ethical Use**: These techniques should only be used for learning and authorized security testing
- **Privilege Requirements**: Many operations require root/administrator privileges

## 📚 Educational Resources

### Documentation
- `Sniffing_Spoofing.pdf`: Complete lab assignment with detailed instructions
- `FInal Assignment Documentation.pdf`: Student solution report with explanations

### Key Learning Concepts
1. **Network Protocol Analysis**: Understanding packet structure and headers
2. **Security Vulnerabilities**: Identifying common attack vectors
3. **Defensive Mechanisms**: Learning how to detect and prevent attacks
4. **Programming Skills**: Developing network security tools

## 🤝 Contributing

This is an educational project. Contributions should focus on:
- Improving documentation
- Adding new educational examples
- Enhancing security awareness
- Bug fixes and code improvements


## 🆘 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure you're running with appropriate privileges
2. **Interface Not Found**: Update interface names in the code to match your system
3. **Docker Issues**: Verify Docker is running and containers are properly started
4. **Library Dependencies**: Install required development libraries for C compilation

### Getting Help
- Check the packet capture files for expected output
- Review the solution documentation for detailed explanations
- Ensure your lab environment matches the provided Docker setup

---

**Note**: This laboratory is part of a network security curriculum and should be used responsibly in educational settings only. 
