# Peer-2-Peer File Sharing System

A distributed peer-to-peer file sharing application built in C++ that allows multiple client nodes to connect, discover, and exchange files in a decentralized network.

## Overview

This project implements a **P2P (Peer-to-Peer) network** where independent clients can:
- Connect to neighboring peers
- Share and discover files
- Exchange metadata with other nodes
- Operate in a fully decentralized manner

The system progresses through 5 phases, each adding more sophisticated features to the P2P network.

## Features

✅ **Socket-based Networking** - Uses TCP/IP for reliable peer communication  
✅ **Multi-client Support** - Handle multiple simultaneous peer connections  
✅ **Configuration-driven** - Easy setup via configuration files  
✅ **File Sharing** - Share files from designated directories  
✅ **Neighbor Discovery** - Automatic peer discovery based on configuration  
✅ **5 Progressive Phases** - Each phase adds enhanced functionality  
✅ **Cross-platform** - Runs on Linux, macOS, and Windows (WSL/MinGW)  

## System Architecture

### Five Phases:

| Phase | Description |
|-------|-------------|
| **Phase 1** | Basic peer discovery and socket connection setup |
| **Phase 2** | File listing exchange between connected peers |
| **Phase 3** | Advanced file distribution and replication |
| **Phase 4** | Optimized peer selection and routing |
| **Phase 5** | Complete P2P implementation with all features |

## Requirements

- **Compiler**: G++ with C++17 support
- **Libraries**: 
  - OpenSSL (libssl-dev, libcrypto)
  - POSIX-compliant system (Linux, macOS, or WSL on Windows)
- **Build Tool**: GNU Make

### Installation of Dependencies

**On Ubuntu/Debian:**
```bash
sudo apt-get install build-essential libssl-dev
```

**On macOS:**
```bash
brew install openssl
```

**On Windows (WSL):**
```bash
sudo apt-get install build-essential libssl-dev
```

## Compilation

Compile all phases:
```bash
make
```

Compile a specific phase:
```bash
g++ -g client-phase1.cpp -lssl -lcrypto -pthread -std=c++17 -o client-phase1
```

Clean build artifacts:
```bash
make clean
```

## Configuration

Each client requires a configuration file specifying:
1. **Client number** - Unique identifier for this client
2. **Port** - Port number to listen on
3. **Private ID** - Internal identifier
4. **Neighbors** - List of neighboring peers with their ports

### Config File Format

**Example: `client1-config.txt`**
```
1                    # Client number
5000                 # Port to listen on
101                  # Private ID
2                    # Number of neighbors
2 5001              # Neighbor client 2 on port 5001
3 5002              # Neighbor client 3 on port 5002
5                    # Number of files
file1.txt
file2.txt
file3.txt
file4.pdf
file5.doc
```

## Directory Structure

```
Peer-2-Peer-main/
├── client-phase1.cpp      # Phase 1: Basic P2P setup
├── client-phase2.cpp      # Phase 2: File listing
├── client-phase3.cpp      # Phase 3: Advanced distribution
├── client-phase4.cpp      # Phase 4: Optimization
├── client-phase5.cpp      # Phase 5: Complete P2P
├── makefile               # Build configuration
├── run.sh                 # Run script for testing
└── README.md             # This file
```

## Usage

### Single Client Execution

Run a single client with its configuration:
```bash
./client-phase1 ./config/client1-config.txt ./files/client1/
```

**Parameters:**
- `config/client1-config.txt` - Path to client configuration file
- `files/client1/` - Path to directory containing files to share

### Multi-client Testing

Run multiple clients simultaneously using the run script:
```bash
./run.sh <config_directory> <num_clients> <phase_number>
```

**Example:**
```bash
./run.sh myconfig 3 1
# Runs phase 1 with 3 clients using configs from myconfig/ directory
```

**Output:**
- Results saved to `output/` directory
- Format: `op-c<client_id>-p<phase>.txt`

## Example Setup

1. **Create directory structure:**
```bash
mkdir -p config files/client1 files/client2 files/client3
mkdir output
```

2. **Create config files:**
```bash
# config/client1-config.txt
1 5000 101 2
2 5001
3 5002
3
file1.txt
file2.txt
file3.txt

# config/client2-config.txt
2 5001 102 2
1 5000
3 5002
2
doc1.pdf
doc2.pdf

# config/client3-config.txt
3 5002 103 2
1 5000
2 5001
2
data1.csv
data2.csv
```

3. **Add files to directories:**
```bash
touch files/client1/file1.txt files/client1/file2.txt files/client1/file3.txt
touch files/client2/doc1.pdf files/client2/doc2.pdf
touch files/client3/data1.csv files/client3/data2.csv
```

4. **Compile and Run:**
```bash
make
./run.sh config 3 1
```

5. **Check Results:**
```bash
cat output/op-c1-p1.txt
cat output/op-c2-p1.txt
cat output/op-c3-p1.txt
```

## Technical Details

### Key Components

- **Socket Management** - Uses `poll()` for efficient multi-socket I/O multiplexing
- **Network Protocol** - TCP-based communication with custom message format
- **File Discovery** - Directory scanning to identify available files
- **Client Registry** - Maintains list of neighbors and their network details
- **Message Queue** - Handles pending messages between peers

### Network Communication

Each client:
1. Creates a **listening socket** on its designated port
2. **Connects to neighbors** based on configuration
3. **Sends/receives messages** using poll-based I/O
4. **Manages file information** and shares with peers
5. **Handles multiple connections** simultaneously

## Compilation Flags

```
-g              # Debug symbols
-std=c++17      # C++17 standard
-lssl -lcrypto  # OpenSSL libraries
-pthread        # POSIX threading support
```

## Troubleshooting

**Issue: "Address already in use"**
```bash
# Wait a moment and try again, or use a different port
lsof -i :5000  # Check if port is in use
kill -9 <PID>  # Force close if needed
```

**Issue: Permission denied on run.sh**
```bash
chmod +x run.sh
```

**Issue: Missing OpenSSL libraries**
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# macOS
brew install openssl
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

## Performance Considerations

- **Scalability**: Tested with up to 5+ simultaneous clients
- **Timeout**: 60-second default timeout per client run
- **Message Size**: Max 800 bytes per message (MAXDATASIZE)
- **Concurrent Connections**: Dynamically resized poll array

## License

This project is part of a distributed systems course/assignment.

## Author

Created as an educational project to understand peer-to-peer networking concepts.

## Contributing

This is an educational project. Feel free to fork, study, and extend!

## Support

For questions or issues:
1. Check the troubleshooting section
2. Review configuration files for correctness
3. Verify all neighbors are reachable on specified ports
4. Check system logs for network errors

---

**Last Updated**: January 2026  
**Status**: Complete with 5 phases
