import requests
import binascii
from neo.Core.TX.Transaction import ContractTransaction
from neocore.IO.BinaryWriter import BinaryWriter
from neo.IO.MemoryStream import StreamManager
from neo.Core.Witness import Witness


def deploy(from_addr, bytecode, contract_params, return_type, details):
    response = requests.post('http://127.0.0.1:20332', json={
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'mw_construct_deploy_tx',
            'params': {
                'from_addr': from_addr,
                'bin': bytecode,
                'contract_params': contract_params,
                'return_type': return_type,
                'details': details,
    }}).json()
    if 'error' in response:
        print(response['error']['message'])
        return
    context = response['result']['context']
    binary_tx = response['result']['tx']
    contract_hash = response['result']['hash']

    tx = ContractTransaction.DeserializeFromBufer(binascii.unhexlify(binary_tx))

    scripts = requests.post('http://127.0.0.1:5000/neo_sign/', json={'binary_tx': binary_tx}).json()
    tx.scripts = [Witness(
            x['invocation'].encode(),
            x['verification'].encode(),
    ) for x in scripts]


    ms = StreamManager.GetStream()
    writer = BinaryWriter(ms)
    tx.Serialize(writer)
    ms.flush()
    signed_tx = ms.ToArray()



    return


    response = requests.post('http://127.0.0.1:20332', json={
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'sendrawtransaction',
            'params': [
                    signed_tx.decode(),
            ]
    }).json()

    print('contract hash:', contract_hash)
    print(response)

if __name__ == '__main__':
    if input('sure to deploy? ').lower()[0] == 'y':
        with open('../../Downloads/NEP5.Contract.avm', 'rb') as f:
            bytecode = binascii.hexlify(f.read()).decode()
        deploy('ATmSy12qH2ikKaYkzEQ2SwtfhLAidm4G9b', bytecode, '0710', '05', {
                'name': 'n',
                'description': 'testttt',
                'email': 'e',
                'version': 'v',
                'author': 'a',
        })
