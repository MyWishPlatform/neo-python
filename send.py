import requests
import binascii
from neo.Core.TX.Transaction import ContractTransaction
from neocore.IO.BinaryWriter import BinaryWriter
from neo.IO.MemoryStream import StreamManager
from neo.Core.Witness import Witness


def send(addr_from, addr_to, asset, amount):
    response = requests.post('http://127.0.0.1:20332', json={
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'mw_construct_send_tx',
            'params': {
                    'from': addr_from,
                    'to': addr_to,
                    'asset': asset,
                    'amount': amount,
            }
    }).json()
    print(response)
    context = response['result']['context']
    binary_tx = response['result']['tx']

    tx = ContractTransaction.DeserializeFromBufer(binascii.unhexlify(binary_tx))
    scripts = requests.post('http://127.0.0.1:5000/neo_sign/', json={'binary_tx': binary_tx, 'address': addr_from}).json()
    print('scripts', scripts)
    tx.scripts = [Witness(
            x['invocation'].encode(),
            x['verification'].encode(),
    ) for x in scripts]
 
    print(scripts)
    ms = StreamManager.GetStream()
    writer = BinaryWriter(ms)
    tx.Serialize(writer)
    ms.flush()
    signed_tx = ms.ToArray()

    print(tx.ToJson())

#    print('does not send: return') ; return

    response = requests.post('http://127.0.0.1:20332', json={
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'sendrawtransaction',
            'params': [
                    signed_tx.decode(),
            ]
    }).json()
    print(response)


if __name__ == '__main__':
    if input('sure to send??? ').lower()[0] == 'y':
#        send('ANiYsMFutPjP9hNrpYrJWVKoSfcxwbyFf7', 'AJFTKKCTVsxvXfctQuYeRqFGZhcQC99pKu', 'NEO', 1)
        send('ANiYsMFutPjP9hNrpYrJWVKoSfcxwbyFf7', 'AJFTKKCTVsxvXfctQuYeRqFGZhcQC99pKu', 'GAS', 1)
