import codecs
import ecdsa
import hashlib
import sys

PRIVATE_KEY_LEN = 64
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class BrainWallet:
    def __init__(self):
        self.passphrases = None
        self.private = None
        self.public = None
        self.address = None

    def generate(self, passphrases, rule=1):
        self.passphrases = passphrases
        self.private = self.__passphrases_to_private(rule)
        self.public = self.__private_to_public()
        self.address = self.__public_to_address()
        self.private = self.__private_to_wallet_import_format()

    def __passphrases_to_private(self, rule):
        partial_private_keys = list()
        for passphrase in self.passphrases:
            partial_private_key = hashlib.sha256(passphrase.encode('utf-8')).hexdigest()
            partial_private_keys.append(partial_private_key)
        private_key = partial_private_keys[0][0:16] + partial_private_keys[1][16:32] + partial_private_keys[2][32:48] + partial_private_keys[3][48:64]
        private_key = codecs.encode(codecs.decode(private_key, 'hex'), 'hex')
        return private_key
        private_key = str()
        if rule == 1:
            part_num = len(partial_private_keys)
            for i in range(PRIVATE_KEY_LEN):
                part = (PRIVATE_KEY_LEN + i) % part_num
                private_key += partial_private_keys[part][i]

        private_key = codecs.encode(codecs.decode(private_key, 'hex'), 'hex')
        return private_key

        address =  BrainWallet.generate_address_from_private_key(private_key)
        private_key = BrainWallet.wallet_import_format(private_key)
        return private_key, address

    def generate_address_from_private_key(private_key):
        public_key = BrainWallet.__private_to_public(private_key)
        address = BrainWallet.__public_to_address(public_key)
        return address

    def __private_to_public(self):
        # ECDAS
        private_key_bytes = codecs.decode(self.private, 'hex')
        key = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Add bitcoin byte
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key

    def __public_to_address(self):
        public_key_bytes = codecs.decode(self.public, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        # Run ripemd160 for the SHA256
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        # Add network byte
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        # Double SHA256 to get checksum
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        # Concatenate public key and checksum to get the address
        address_hex_str = (network_bitcoin_public_key + checksum).decode('utf-8')
        address = BrainWallet.hex_to_base58(address_hex_str)
        return address
    
    def __private_to_wallet_import_format(self):
        main_net_byte = b'80'
        private_key_hex = main_net_byte + self.private
        private_key_bytes = codecs.decode(private_key_hex, 'hex')
        sha256_bytes = hashlib.sha256(private_key_bytes).digest()
        sha256_2_bytes = hashlib.sha256(sha256_bytes).digest()
        sha256_2_hex = codecs.encode(sha256_2_bytes, 'hex')
        processed_key_str = (private_key_hex + sha256_2_hex[0:8]).decode('utf-8')
        wif_private_key = BrainWallet.hex_to_base58(processed_key_str)
        return wif_private_key

    @staticmethod
    def hex_to_base58(hex_datum):
        b58_string = str()
        # Get the number of leading zeros and convert hex to decimal
        leading_zeros = len(hex_datum) - len(hex_datum.lstrip('0'))
        # Convert hex to decimal
        dec_datum = int(hex_datum, 16)
        # Append digits to the start of string
        while dec_datum > 0:
            digit = dec_datum % 58
            digit_char = BASE58_ALPHABET[digit]
            b58_string = digit_char + b58_string
            dec_datum //= 58
        # Add '1' for each 2 leading zeros
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string

passphrases = list()
for i, content in enumerate(sys.argv):
    if i == 0:
        continue
    passphrases.append(content)

if passphrases:
    wallet = BrainWallet()
    wallet.generate(passphrases)
    print(f'Passphrase: {passphrases}')
    print(f'PrivateKey: {wallet.private}')
    print(f'PublicKey:  {wallet.address}')
