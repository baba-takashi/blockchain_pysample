import codecs
import hashlib

import base58
from ecdsa import NIST256p
from ecdsa import SigningKey

import utils


class Wallet(object):

    def __init__(self):
        self._private_key = SigningKey.generate(curve=NIST256p)
        self._public_key = self._private_key.get_verifying_key()
        self._blockchain_address = self.generate_blockchain_address()

    @property
    def private_key(self):
        return self._private_key.to_string().hex()

    @property
    def public_key(self):
        return self._public_key.to_string().hex()

    @property
    def blockchain_address(self):
        return self._blockchain_address

    def generate_blockchain_address(self):
        ######################
        # ビットコイン仕様
        ######################
        # 2 パブリックキーでSHA256
        public_key_bytes = self._public_key.to_string()  # パブリックキーの文字列を取得
        sha256_bpk = hashlib.sha256(public_key_bytes)  # パブリックキー文字列（Binary Public Key）をSHA256でハッシュ化
        sha256_bpk_digest = sha256_bpk.digest()  # ハッシュ値を取得する
        # 3 SHA256からRipemd160 ※少し短くなる
        ripemd160_bpk = hashlib.new('ripemd160')  # Ripemd160でバイナリープライベートキーを生成
        ripemd160_bpk.update(sha256_bpk_digest)  # sha256のハッシュ値を設定
        ripemd160_bpk_digest = ripemd160_bpk.digest()  # Ripemd160のハッシュ値を取得
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')  # Ripemd160のハッシュからヘキサを取得
        # 4 ネットワークバイトを追加
        network_byte = b'00'  # バイナリーで00をつける。（メインネットワークではb00を付けるため）
        network_bitcoin_byte_public_key = network_byte + ripemd160_bpk_hex  # ネットワークバイトにRipemd160のヘキサを結合
        network_bitcoin_byte_public_key_bytes = codecs.decode(
            network_bitcoin_byte_public_key, 'hex')  # ヘキサを取得
        # 5 ２回SHA256
        sha256_bpk = hashlib.sha256(network_bitcoin_byte_public_key_bytes)  # 1回目
        sha256_bpk_digest = sha256_bpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_bpk_digest)  # 2回目
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')  # 2回SHA256してヘキサに変換
        # 6 チェックサムを取得
        checksum = sha256_hex[:8]  # 先頭から8バイトを取得
        # 7 パブリックキーとチェックサムを連結
        address_hex = (network_bitcoin_byte_public_key + checksum).decode('utf-8')
        # 8 BASE58でエンコード
        blockchain_address = base58.b58encode(address_hex).decode('utf-8')

        return blockchain_address


class Transaction(object):

    def __init__(self, sender_private_key, sender_public_key
                 , sender_blockchain_address, recipient_blockchain_address
                 , value):
        self.sender_private_key = sender_private_key
        self.sender_public_key = sender_public_key
        self.sender_blockchain_address = sender_blockchain_address
        self.recipient_blockchain_address = recipient_blockchain_address
        self.value = value

    def generate_signature(self):
        sha256 = hashlib.sha256()
        transaction = utils.sorted_dict_by_key({
            'sender_blockchain_address': self.sender_blockchain_address,
            'recipient_blockchain_address': self.recipient_blockchain_address,
            'value': float(self.value)
        })
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()  # ハッシュを求める
        private_key = SigningKey.from_string(
            bytes().fromhex(self.sender_private_key), curve=NIST256p)
        private_key_sign = private_key.sign(message)
        signature = private_key_sign.hex()
        return signature


if __name__ == '__main__':
    wallet_M = Wallet()
    wallet_A = Wallet()
    wallet_B = Wallet()
    # print('private_key        = ' + wallet.private_key)
    # print('public_key         = ' + wallet.public_key)
    # print('blockchain_address = ' + wallet.blockchain_address)

    t = Transaction(
        wallet_A.private_key, wallet_A.public_key, wallet_A.blockchain_address,
        wallet_B.blockchain_address, 1.0)
    print('signature          = ' + t.generate_signature())

    ########### Blockchain Node
    import blockchain
    block_chain = blockchain.BlockChain(
        blockchain_address=wallet_M.blockchain_address)
    is_added = block_chain.add_transaction(
        wallet_A.blockchain_address,
        wallet_B.blockchain_address,
        1.0,
        wallet_A.public_key,
        t.generate_signature())
    print('Added?', is_added)
    block_chain.mining()
    utils.pprint(block_chain.chain)

    print('A', block_chain.calculate_total_amount(wallet_A.blockchain_address))
    print('B', block_chain.calculate_total_amount(wallet_B.blockchain_address))
