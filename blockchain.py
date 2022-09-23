import hashlib
import json
import logging
import sys
import time

from ecdsa import NIST256p
from ecdsa import VerifyingKey

import utils

MINING_DIFFICULTY = 3
MINING_SENDER = 'THE BLOCKCHAIN'
MINING_REWARD = 1.0

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)


class BlockChain(object):

    def __init__(self, blockchain_address=None, port=None):
        self.transaction_pool = []  # 空のトランザクションリスト
        self.chain = []  # 初回は空のチェーンリスト
        self.create_block(0, self.hash({}))
        self.blockchain_address = blockchain_address  # ブロックを生成するのはパラメーターのアドレスとする
        self.port = port

    def create_block(self, nonce, previous_hash):
        block = utils.sorted_dict_by_key({
            'timestamp': time.time(),
            'transactions': self.transaction_pool,
            'nonce': nonce,
            'previous_hash': previous_hash
        })
        self.chain.append(block)  # 現在のトランザクションをすべて入れたブロックをチェーン配列の追加
        self.transaction_pool = []  # ブロックを生成したらトランザクションをクリアする
        return block

    def hash(self, block):
        sorted_block = json.dumps(block, sort_keys=True)  # sort_keys＝文字列にする（Json.dumps）の場合にソートさせる
        return hashlib.sha256(sorted_block.encode()).hexdigest()  # ソートしたブロックを16進にエンコードしてハッシュを求める

    def add_transaction(self, sender_blockchain_address
                        , recipient_blockchain_address, value
                        , sender_public_key=None, signature=None):  # トランザクションに送受信アドレスと内容を追加
        transaction = utils.sorted_dict_by_key({
            'sender_blockchain_address': sender_blockchain_address,
            'recipient_blockchain_address': recipient_blockchain_address,
            'value': float(value)
        })

        if sender_blockchain_address == MINING_SENDER:
            self.transaction_pool.append(transaction)
            return True

        if self.verify_transaction_signature(
                sender_public_key, signature, transaction):

            # if self.calculate_total_amount(sender_blockchain_address) < float(value):
            #     logger.error({'action': 'add_transaction', 'error': 'no'})
            #     return False

            self.transaction_pool.append(transaction)
            return True

        return False

    def verify_transaction_signature(
            self, sender_public_key, signature, transaction):
        sha256 = hashlib.sha256()
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()
        signature_bytes = bytes().fromhex(signature)
        verifying_key = VerifyingKey.from_string(
            bytes().fromhex(sender_public_key), curve=NIST256p)
        verified_key = verifying_key.verify(signature_bytes, message)
        return verified_key

    def valid_proof(self, transactions, previous_hash, nonce,
                    difficulty=MINING_DIFFICULTY):  # 妥当な証明であるかをチェック
        guess_block = utils.sorted_dict_by_key({
            'transactions': transactions,
            'nonce': nonce,
            'previous_hash': previous_hash
        })
        guess_block = self.hash(guess_block)  # チェックするブロック
        chk_bool = guess_block[:difficulty] == '0'*difficulty  # 先頭からDifficultyまでの文字列が０かをチェック
        return chk_bool

    def proof_of_work(self):
        transactions = self.transaction_pool.copy()  # 現在のトランザクションいったんコピー
        previous_hash = self.hash(self.chain[-1])  # ひとつ前のブロックのハッシュ値
        nonce = 0  # ひとまず０からチェックする
        while self.valid_proof(transactions, previous_hash, nonce) is False:  # 妥当なナンスが見つかるまでループ
            nonce += 1
        return nonce

    def mining(self):  # マイニング作業を定義
        self.add_transaction(
            sender_blockchain_address=MINING_SENDER,  # リワードを発行するブロックチェーンアドレス
            recipient_blockchain_address=self.blockchain_address,  # リワードの送付先アドレス
            value=MINING_REWARD  # リワード額
        )
        nonce = self.proof_of_work()  # ナンスを求める
        previous_hash = self.hash(self.chain[-1])  # ひとつ前のブロックのハッシュ値
        self.create_block(nonce, previous_hash)  # ブロック生成
        logger.info({'action': 'mining', 'status': 'success'})  # ログ
        return True

    def calculate_total_amount(self, blockchain_adress):
        total_amount = 0.0
        for block in self.chain:
            for transaction in block['transactions']:
                value = float(transaction['value'])
                if blockchain_adress == transaction['recipient_blockchain_address']:
                    total_amount += value
                if blockchain_adress == transaction['sender_blockchain_address']:
                    total_amount -= value
        return total_amount


if __name__ == '__main__':  # 自身を実行
    my_blockchain_address = 'My_blockchain_address'  # 自身のウォレットのアドレス
    block_chain = BlockChain(blockchain_address=my_blockchain_address)
    utils.pprint(block_chain.chain)

    block_chain.add_transaction('A', 'B', 1.0)
    block_chain.mining()
    utils.pprint(block_chain.chain)

    block_chain.add_transaction('C', 'D', 2.0)
    block_chain.add_transaction('X', 'Y', 3.0)
    block_chain.mining()
    utils.pprint(block_chain.chain)

    print('my', block_chain.calculate_total_amount(my_blockchain_address))
    print('C', block_chain.calculate_total_amount('C'))
    print('D', block_chain.calculate_total_amount('D'))
