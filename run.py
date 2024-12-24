from qiskit import QuantumCircuit
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
from ecdsa import SigningKey, SECP256k1
import hashlib
import base58
 
token = "c36005ba60b911dd177ee3734965c40481aad21395b2b490812f2ab9d9d69235b9fe7f33545d3df9904af42bc1a72033784f30d0152009833b67a06b0a35b911"

# Save IBM Quantum account credentials (if not already saved)
QiskitRuntimeService.save_account(
    token=token,
    channel="ibm_quantum",
    overwrite=True
)

# Function to generate a Bitcoin address from a private key
def generate_bitcoin_address(private_key):
    # Convert the private key to a SigningKey object (ECC key)
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    
    # Generate the public key
    public_key = sk.verifying_key.to_string("compressed").hex()
    
    # Perform SHA-256 hashing on the public key
    sha256_hash = hashlib.sha256(bytes.fromhex(public_key)).digest()
    
    # Perform RIPEMD-160 hashing on the result
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # Add the network byte (0x00 for Bitcoin Mainnet) to the RIPEMD-160 hash
    network_byte = b'\x00'  # Mainnet prefix
    payload = network_byte + ripemd160_hash
    
    # Perform double SHA-256 hashing to calculate the checksum
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    
    # Add the checksum to the payload
    binary_address = payload + checksum
    
    # Encode the final binary address into Base58Check
    bitcoin_address = base58.b58encode(binary_address).decode()
    return bitcoin_address

# Function to generate private keys using quantum randomness
def generate_private_keys(num_keys, num_bits_per_round=64):
    # Create a quantum circuit to measure `num_bits_per_round` bits
    qc = QuantumCircuit(num_bits_per_round)
    qc.measure_all()
    
    # Load IBM Quantum Runtime Service
    service = QiskitRuntimeService()

    # Select the least busy backend
    backend = service.least_busy(operational=True, simulator=False)
    
    # Create a sampler
    sampler = Sampler(backend)
    
    # Extract bitstrings and convert to private keys
    private_keys = []
    
    for _ in range(num_keys):
        random_bits = ""
        
        while len(random_bits) < 256:
            job = sampler.run([qc])
            print(f"Job ID: {job.job_id()}")
            result = job.result()
            quasi_distribution = result.quasi_distribution[0]
            
            # Extract the bitstring with the highest probability
            bitstring = max(quasi_distribution, key=quasi_distribution.get)
            random_bits += bitstring
        
        private_key = hex(int(random_bits[:256], 2))[2:].zfill(64)
        private_keys.append(private_key)
    
    return private_keys

# Main function to generate wallet pairs
def main(num_wallets):
    print(f"Generating {num_wallets} Bitcoin wallet(s) using Quantum Randomness...\n")
    private_keys = generate_private_keys(num_wallets)
    wallets = []
    
    for private_key in private_keys:
        bitcoin_address = generate_bitcoin_address(private_key)
        wallets.append((private_key, bitcoin_address))
    
    for i, (private_key, bitcoin_address) in enumerate(wallets, 1):
        print(f"Wallet {i}:\n  Private Key: {private_key}\n  Bitcoin Address: {bitcoin_address}\n")
    
    return wallets

# Execute the script
if __name__ == "__main__":
    num_wallets = 5  # Change this to generate more wallets
    wallets = main(num_wallets)
