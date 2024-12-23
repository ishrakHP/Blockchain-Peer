# Blockchain Peer System

This project demonstrates the implementation of a blockchain peer system using UDP communication, synchronization, consensus algorithms, and messaging strategies. The system features proof-of-work mining and gossip-based peer discovery and state management.

## Features

### Core Functionality
- **Blockchain Management**:
  - Stores messages in blocks with attributes such as miner name, messages, nonce, height, and cryptographic hash.
  - Ensures block validation and chain synchronization.
- **Proof-of-Work Consensus**:
  - Implements mining to find a valid nonce that satisfies the difficulty level.
  - Uses cryptographic hashing via Python's `hashlib` for block validation.
- **Peer Discovery and Gossip Protocol**:
  - Peers use a gossip protocol to announce themselves and maintain a network connection.
  - GOSSIP messages are sent every 30 seconds and expire after 1 minute.
- **UDP Communication**:
  - All communication between peers, including chain synchronization and gossiping, is handled via UDP.
- **Fault Tolerance**:
  - Handles lost messages with retries for critical operations like blockchain synchronization.

### Optional Bonus Features
- **Mining Enhancements**:
  - Single-threaded periodic mining.
  - Multi-threaded mining for continuous block discovery.
  - External mining clients communicating via TCP.
- **Web Server Integration**:
  - View blockchain status through a web interface (e.g., `http://silicon.cs.umanitoba.ca:8998`).

## Technologies Used
- **Programming Language**: Python
- **Libraries**: `hashlib`, `socket`, `uuid`, `random`
- **Communication Protocol**: UDP
- **Consensus Algorithm**: Proof-of-Work

## Protocol Details

### GOSSIP
- Announce peer information to the network.
- GOSSIP messages include the peer's name, host, port, and a unique ID.
- Received GOSSIP messages trigger a GOSSIP_REPLY to the sender.

### Blockchain Synchronization
- **GET_BLOCK**: Requests a block by height from peers.
- **GET_BLOCK_REPLY**: Responds with the requested block or `None` if unavailable.
- Peers synchronize to the longest valid chain by fetching missing blocks and validating the entire chain.

### Statistics and Consensus
- **STATS**: Requests the height and hash of the chain from peers.
- **STATS_REPLY**: Provides the chain's height and hash.
- **CONSENSUS**: Forces immediate chain validation and synchronization.

## Setup and Running the Project

### Prerequisites
- Python 3.0
- Required Libraries: `socket`, `hashlib`, `uuid`, `random`

### Steps to Run
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-folder>
   ```
2. Start the blockchain peer:
   ```bash
   python3 peer.py
   ```
3. Connect to the network via a well-known host (e.g., `silicon.cs.umanitoba.ca:8999`).
4. View peer status through the web interface (if enabled).

### Synchronization Time

- The program performs consensus as soon as it enters the network (upon receiving the first gossip-reply, usually from the well-known host). If the well-known host is synchronized, the peer becomes synchronized immediately.
- If the well-known host is not synchronized, the peer waits for two minutes to perform another consensus and synchronize.
- After performing consensus, the peer prints the height and hash of the last block.

### Consensus Code

- Consensus is handled by the `perform_consensus()` function (lines 169 - 242).
- **Process:**
  1. Collects `STATS-REPLY` messages from all active peers and stores them in a list called `peer_heights` (lines 182 - 203).
  2. Sorts the list by height (line 208).
  3. Loops through the list from highest to lowest height to find the valid chain, optimized by checking the hash (lines 219 - 242).

### Removing Inactive Peers

- Inactive peers are removed in the main loop (lines 504 - 509).
- **Cleanup Process:**
  - The peer-list includes a key called `last-active`. Each time it hears a gossip message, it updates the `last-active` value with the current time of the originator.
  - During each loop iteration, it checks if `last-active` exceeds one minute. If so, it removes the peer from the list.

### Verifying the Entire Chain

- Verifies all blocks and the entire chain up to the block being added.
- Blocks are verified using the `validate_block()` function (lines 315 - 340).
- The `calculate_block_hash()` function (lines 297 - 312) verifies the block with respect to the current chain. This function is also called inside `validate_block()`, ensuring the entire chain is verified up to that block.

## Testing
- **GOSSIP Protocol**: Use tools like `netcat` or custom scripts to simulate GOSSIP messages.
- **Blockchain Synchronization**: Validate blocks by fetching chains from peers.
- **Mining**: Run periodic or continuous mining to append blocks to the chain.

## Project Structure
- `peer.py`: Main peer program handling UDP communication and blockchain operations.
- `blockchain.py`: Blockchain logic, including validation, hashing, and synchronization.
- `gossip.py`: Gossip protocol implementation.

## Challenges and Learning Outcomes
- Implemented efficient UDP-based peer-to-peer communication.
- Designed a robust proof-of-work consensus mechanism.
- Developed fault-tolerant blockchain synchronization and validation.
- Gained hands-on experience with distributed systems and cryptographic hashing.

## Potential Improvements
- Add persistent storage for the blockchain.
- Enhance mining efficiency and scalability.
- Optimize message handling to reduce network overhead.
