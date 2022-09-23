from flask import Flask
from flask import jsonify
from flask import render_template

import wallet

app = Flask(__name__, template_folder='./templates')


@app.route('/')
def index():
    return render_template('/index.html')

@app.route('/wallet', methods=['POST'])
def create_wallet():
    my_wallet = wallet.Wallet()
    response = {
        'private_key': my_wallet.private_key,
        'public_key': my_wallet.public_key,
        'blockchain_address': my_wallet.blockchain_address
    }
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080,
                        type=int, help='port to listen on')
    parser.add_argument('-g', '--gw', default='http://127.0.0.1:5000',
                        type=str, help='blockchain gateway')
    args = parser.parse_args()
    port = args.port
    app.config['gw'] = args.gw

    # サーバーを立ち上げる
    app.run(host='0.0.0.0', port=port, threaded=True, debug=True)
