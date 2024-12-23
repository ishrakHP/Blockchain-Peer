#-----------------------------------------
# NAME: Hasin Ishrak 
# 
# 
# 
# 
# 
# 
# REMARKS: Creating a Blockchain peer that 
#           stores messages in blocks
#
#-----------------------------------------



import json
import socket
import time
import random
import uuid
import random
import hashlib

# Constants
WELL_KNOWN_HOST = 'silicon.cs.umanitoba.ca'
WELL_KNOWN_HOST_PORT = 8999
GOSSIP_REPEAT_COUNT = 3 # Repeat Gossip up to 3 peers
DROP_THRESHOLD = 60  # Remove a peer if not been heard from a minute
SERVER_PORT = 8359  # Change to the desired port
DIFFICULTY = 9 # Number of trailing zeros
CONSENSUS_INTERVAL = 119 # Do a consensus in every 2 minutes

# Peer variables
peer_list = [] # Tracks the peers in the list
gossiped_id = [] # Tracks already gossiped messages
blockchain = [] # The real-chain of blocks

# Function to gossip to a well-known host
def gossip(peer_id, well_known_host, well_known_port):

    gossip_message = {
        "type": "GOSSIP",
        "host": socket.gethostbyname(socket.gethostname()),
        "port": SERVER_PORT,
        "id": peer_id,
        "name": "H!"
    }

    try:
        # Send the gossip message to the well-known host
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(json.dumps(gossip_message).encode('utf-8'), (well_known_host, well_known_port))
    except Exception as e:
        print(f"Error in gossiping: {e}")

# Function to handle incoming gossip messages
def reply_to_gossip(message):
    reply_message = {
        "type": "GOSSIP_REPLY",
        "host": socket.gethostbyname(socket.gethostname()),
        "port": SERVER_PORT,
        "name": "H!"
    }

    # Reply to the originator of the gossip message
    originator_host = message["host"]
    originator_port = message["port"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(json.dumps(reply_message).encode('utf-8'), (originator_host, originator_port))
    except Exception as e:
        print(f"Error in replying to gossip: {e}")


# Function to repeat gossip to a peer
def repeat_gossip(message, host, port):

    gossip_message = {
        "type": "GOSSIP",
        "host": message["host"],
        "port": message["port"],
        "id": message["id"],
        "name": message["name"]
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(json.dumps(gossip_message).encode('utf-8'), (host, port))
    except Exception as e:
        print(f"Error in gossiping: {e}")


# Function to get statistics about the chain
def get_chain_stats():
    stats_reply = {
        "type": "STATS_REPLY",
        "height": None,
        "hash": None
    }
    if (len(blockchain) > 0):
        max_height_block = max(blockchain, key=lambda block: block["height"])
        stats_reply = {
            "type": "STATS_REPLY",
            "height": max_height_block["height"]+1,
            "hash": max_height_block["hash"]
        }
    return stats_reply


# Function to request a single block from a peer
def request_single_block(peer, height):
    get_block_message = {
        "type": "GET_BLOCK",
        "height": height
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.02)
            s.sendto(json.dumps(get_block_message).encode('utf-8'), (peer["host"], peer["port"]))
            # print(f"Sent GET_BLOCK request to {peer['host']}:{peer['port']} for height {height}")
            data, addr = s.recvfrom(4096)
            # print("Received GET_BLOCK_REPLY response")
            # print(data.decode('utf-8'))
            return json.loads(data.decode('utf-8'))
    except Exception as e:
        print(f"Error in sending or getting {height} GET_BLOCK request: {e}")

    return None



# Function to handle GET_BLOCK protocol
def handle_get_block(request, host, port):
    requested_height = request["height"]
    block_reply = {
        "type": "GET_BLOCK_REPLY",
        "hash": None,
        "height": None,
        "messages": None,
        "minedBy": None,
        "nonce": None,
        "timestamp": None,
    }

    # Find the block with the requested height
    for block in blockchain:
        if block["height"] == requested_height:
            block_reply = {
                "type": "GET_BLOCK_REPLY",
                "hash": block["hash"],
                "height": block["height"],
                "messages": block["messages"],
                "minedBy": block["minedBy"],
                "nonce": block["nonce"],
                "timestamp": int(block["timestamp"]),  # Current timestamp
            }
            break

    # Send the GET_BLOCK_REPLY to the requester
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(json.dumps(block_reply).encode('utf-8'), (host, port))
            # print("replied to ", host, " ", port)
    except Exception as e:
        print(f"Error in sending GET_BLOCK_REPLY: {e}")


def perform_consensus():

    # Check we have enough peers:
    if (len(peer_list) < 1):
        print("Not enought peers.")
        return
    
    # Set a timeout for receiving responses
    timeout = 0.05

    # List to store peers with their chain information
    peer_heights = []

    for peer in peer_list:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(json.dumps({"type": "STATS"}).encode('utf-8'), (peer["host"], peer["port"]))
                data, adrs = s.recvfrom(4096)
                stats_response = json.loads(data.decode('utf-8'))
                if stats_response["type"] == "STATS_REPLY": 
                    if (isinstance(stats_response["height"], int) and isinstance(stats_response["hash"], str) and stats_response["height"] != None and stats_response["hash"] != None and stats_response["hash"] != ""):
                        peer_heights.append((stats_response["height"], stats_response["hash"], peer))
                else:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                            s.sendto(json.dumps({"type": "Busy doing consensus!"}).encode('utf-8'), (adrs[0], adrs[1]))
                    except Exception as e:
                        print(f"Error in sending reply: {e}")
        except Exception as e:
            print(f"Error in requesting STATS from {peer}: {e}")

    if not peer_heights:
        print("No responses received during consensus.")
        return
    
    # print("\npeer-heights: \n", peer_heights)

    # Sort the peers based on height in descending order
    peer_heights.sort(reverse=True, key=lambda x: x[0])

    # chech if the height of the consensused chain in greater than the current chain height
    higest_height_peer = peer_heights[0]
    higest_height, _, _ = higest_height_peer
    current_height = get_chain_stats()["height"]
    print("Highest height amongst peers: ", higest_height, ", Current height of this peer: ", current_height)
    if (current_height != None and current_height >= higest_height):
        print("This chain has the highest height!")
        return

    for x in range(len(peer_heights)):

        # Choose the one with the highest height (first element in the sorted list)
        agreed_upon_peer = peer_heights[x]
        agreed_height, agreed_hash, agreed_peer = agreed_upon_peer

        prev_peer = peer_heights[x-1]
        prev_height, prev_hash, agreed_peer = prev_peer
        
        if (x>0 and agreed_height == prev_height and agreed_hash == prev_hash):
            print("\nSame properties as the previous one! Moving to the next chain...")
            continue

        print(f"Agreed upon chain: Height={agreed_height}, Hash={agreed_hash}")

        agreed_peers = [(height, hash, peer) for height, hash, peer in peer_heights if height == agreed_height and hash == agreed_hash]

        print("Agreed Peers: \n", agreed_peers, "\n")

        # Load the agreed-upon chain
        if (load_chain(agreed_height, agreed_hash, agreed_peers)):
            break

        print("\nMoving to the next chain...")

def load_chain(height, hash, agreed_peers):
    for block_height in range(height):  # Load blocks up to the agreed height

        # Try to receive the block
        # _, _, peer = random.choice(agreed_peers)
        # block_reply = request_single_block(peer, block_height)
        block_received = False
        while not block_received:

            _, _, peer = random.choice(agreed_peers)
            block_reply = request_single_block(peer, block_height)

            if block_reply != None and block_reply["type"] == "GET_BLOCK_REPLY":

                if (not any(value is None for value in block_reply.values())) and (validate_block(block_reply)):
                    block_received = True

                    # Check if a block with the same height already exists in the blockchain
                    existing_block = next((block for block in blockchain if block["height"] == block_reply["height"]), None)

                    if existing_block:
                        # Update the existing block with the new content
                        existing_block.update({
                            "hash": block_reply["hash"],
                            "messages": block_reply["messages"],
                            "minedBy": block_reply["minedBy"],
                            "nonce": block_reply["nonce"],
                            "timestamp": block_reply["timestamp"],
                        })
                        print(f"Updated existing block {block_reply['height']} from {peer['host']}:{peer['port']}")
                    else:
                        # Append the new block to the blockchain
                        blockchain.append({
                            "height": block_reply["height"],
                            "hash": block_reply["hash"],
                            "messages": block_reply["messages"],
                            "minedBy": block_reply["minedBy"],
                            "nonce": block_reply["nonce"],
                            "timestamp": block_reply["timestamp"],
                        })
                        print(f"Received and appended new block {block_reply['height']} from {peer['host']}:{peer['port']}")
                else:
                    if any(value is None for value in block_reply.values()):
                        continue
                    else:
                        return False
            else:
                continue

    return True


# Function to calculate the hash of a block
def calculate_block_hash(block):
    hash_base = hashlib.sha256()

    if block["height"] > 0:
        lastHash = lastBlockHash(block["height"])
        hash_base.update(lastHash.encode())

    hash_base.update(block["minedBy"].encode())

    for message in block["messages"]:
        hash_base.update(message.encode())

    hash_base.update(int(block["timestamp"]).to_bytes(8, 'big'))
    hash_base.update(block["nonce"].encode())

    return hash_base.hexdigest()

# Function to validate a block
def validate_block(block):
    # Check required fields
    required_fields = ['minedBy', 'messages', 'timestamp', 'nonce']

    if block["height"] > 0:
        required_fields.append('hash')

    for field in required_fields:
        if field not in block:
            print(f"Block {block['height']} is missing required field: {field}")
            return False

    # Calculate the hash for this block
    calculated_hash = calculate_block_hash(block)

    # Check if the hash is correct
    if calculated_hash != block['hash']:
        print(f"Block {block['height']} does not have the correct hash!")
        return False

    # Check difficulty
    if calculated_hash[-DIFFICULTY:] != '0' * DIFFICULTY:
        print(f"Block {block['height']} was not difficult enough: {calculated_hash}")
        return False

    return True


# Function that verifies the new announced block and adds it to the chain
def handle_announcement(received_message, host, port):
    current_height = get_chain_stats()["height"]-1
    if any(value is None for value in received_message.values()):
        print("New announced block is not valid! Has emplty fields")
        return
    elif (current_height != None and current_height >= received_message["height"]):
        print("New announced block is not valid! Height is less than or equal to the current highest height")
        return
    elif validate_block(received_message):
        blockchain.append({
            "height": received_message["height"],
            "hash": received_message["hash"],
            "messages": received_message["messages"],
            "minedBy": received_message["minedBy"],
            "nonce": received_message["nonce"],
            "timestamp": received_message["timestamp"],
        })
        print(f"\nReceived and appended newly announced block with height of {received_message['height']} from: {host}:{port}")
    else:
        print("Failed to validate newly announced block.")
    
    return True


# Function that takes a height parameter and returns the hash of the block with height - 1
def lastBlockHash(height):
    # Check if the requested height is valid
    if height > 0 and height <= len(blockchain):
        # Get the block with height - 1
        last_block = blockchain[height - 1]
        
        # Return the hash of the last block
        return last_block["hash"]
    else:
        # If the requested height is invalid or the blockchain is empty, return an empty string
        return ""

# Function to repeat GOSSIP message to all peers
def gossip_to_all():
    # Generate a random UUID for this gossip message
    gossip_id = str(uuid.uuid4())
    gossiped_id.append(gossip_id)
    for peer in peer_list:
        gossip(gossip_id, peer["host"], peer["port"])

# Function to print the peer_list
def print_peer_list():
    print("\nCurrent Peer List:")
    for peer in peer_list:
        print(f"Host: {peer['host']}, Port: {peer['port']}, Name: {peer.get('name', 'N/A')}, Last-active: {peer['last_active']}")
    print("\n")

# Main function
if __name__ == "__main__":

    # Gossip message to the well-known host, port
    gossip_id = str(uuid.uuid4())
    gossip(gossip_id, WELL_KNOWN_HOST, WELL_KNOWN_HOST_PORT)
    gossiped_id.append(gossip_id)

    gossip_time = time.time()
    consensus_time = time.time()

    flag = 0 # To indicate perform_consensus when entering the network

    # Main loop
    while True:
        # Repeat GOSSIP message every 29 seconds, sent to all peers
        if (time.time() - gossip_time) > 29:
            gossip_to_all()
            gossip_time = time.time()
            print("\nGossiped!")


        # Check for incoming gossip messages
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            server_socket.bind(("0.0.0.0", SERVER_PORT))
            server_socket.settimeout(1)
            try:
                data, addr = server_socket.recvfrom(4096)
                if data and isinstance(data, bytes):
                    try:
                        received_message = json.loads(data.decode('utf-8'))
                        # Now process the received JSON message

                        # print("received ---->" , received_message)
                    
                        if isinstance(received_message, dict) and "type" in received_message:
                            # Handle different types of messages
                            if received_message["type"] == "GOSSIP":
                                if received_message["id"] not in gossiped_id:
                                    
                                    # Add the originator to the peer list if not already present
                                    if not any(peer["host"] == received_message["host"] and peer["port"] == received_message["port"] for peer in peer_list):
                                        peer_list.append({
                                            "host": received_message["host"],
                                            "port": received_message["port"],
                                            "name": received_message["name"],
                                            "last_active": time.time()
                                        })
                                    else:
                                        for peer in peer_list:
                                            if peer["host"] == received_message["host"] and peer["port"] == received_message["port"]:
                                                peer["last_active"] = time.time()
                                    
                                    # Reply but not repeat GOSSIP messages and repeat to 3 peers
                                    if received_message["id"] not in gossiped_id:
                                        gossiped_id.append(received_message["id"])
                                        reply_to_gossip(received_message)
                                        for peer in random.sample(peer_list, min(GOSSIP_REPEAT_COUNT, len(peer_list))):
                                            repeat_gossip(received_message, peer["host"], peer["port"])


                            elif received_message["type"] == "GOSSIP_REPLY":
                                # Add the sender to the peer list if not already present
                                if not any(peer["host"] == received_message["host"] and peer["port"] == received_message["port"] for peer in peer_list):
                                    peer_list.append({
                                        "host": received_message["host"],
                                        "port": received_message["port"],
                                        "name": received_message["name"],
                                        "last_active": time.time()
                                })
                                    

                            # Handle STATS message
                            elif received_message["type"] == "STATS":
                                stats_reply = get_chain_stats()
                                if stats_reply is not None:
                                    try:
                                        json_stats_reply = json.dumps(stats_reply).encode('utf-8')
                                        server_socket.sendto(json_stats_reply, (addr[0], addr[1]))
                                    except json.JSONDecodeError as e:
                                        print(f"Error encoding stats_reply to JSON: {e}")


                            # Handle GET_BLOCK message
                            elif received_message["type"] == "GET_BLOCK":
                                handle_get_block(received_message, addr[0], addr[1])


                            # Handle a new block announcement
                            elif received_message["type"] == "ANNOUNCE":
                                print("\nHandling newly announced block..")
                                handle_announcement(received_message, addr[0], addr[1])


                            # Handle a consensus request
                            elif received_message["type"] == "CONSENSUS":
                                print("\nHandling consensus request...")
                                perform_consensus()
                                max_height_block = max(blockchain, key=lambda block: block["height"])
                                print("\nThe status of the last block of the chain { height: ", max_height_block["height"], "}, {hash: ", max_height_block["hash"], "}")


                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON: {e}")

            except socket.timeout:
                pass

        # Remove peers not heard from in a minute
        current_time = time.time()
        size_of_list = len(peer_list)
        peer_list = [peer for peer in peer_list if current_time - peer.get("last_active", 0) <= DROP_THRESHOLD]
        if (len(peer_list) < size_of_list):
            print("\nSome peers were removed...")

        # Do consensus when entering network -> there is at-least one peer in the network
        if (len(peer_list) >= 1 and flag == 0):
            print("\nDoing consensus upon entering the network...")
            perform_consensus()
            max_height_block = max(blockchain, key=lambda block: block["height"])
            print("\nThe status of the last block of the chain { height: ", max_height_block["height"], "}, {hash: ", max_height_block["hash"], "}")
            flag = flag+1

        # Perform consensus in every two minutes
        if (len(peer_list) > 1) and time.time() - consensus_time > CONSENSUS_INTERVAL:
            print("\nBusy doing consensus...")
            perform_consensus()
            max_height_block = max(blockchain, key=lambda block: block["height"])
            print("\nThe status of the last block of the chain { height: ", max_height_block["height"], "}, {hash: ", max_height_block["hash"], "}")
            consensus_time = time.time()


    print("Exiting the peer.")
