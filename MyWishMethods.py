from neo.Core.Blockchain import Blockchain
from neo.Core.TX.Transaction import TransactionOutput, ContractTransaction
from neo.Core.TX.TransactionAttribute import TransactionAttribute, TransactionAttributeUsage
from neo.SmartContract.ContractParameterContext import ContractParametersContext
from neo.Network.NodeLeader import NodeLeader
from neo.Prompt.Utils import get_arg, get_from_addr, get_asset_id, lookup_addr_str, get_tx_attr_from_args
from neo.Prompt.Commands.Tokens import do_token_transfer, amount_from_string
from neo.Wallets.NEP5Token import NEP5Token
from neocore.UInt256 import UInt256
from neocore.Fixed8 import Fixed8
import json
from prompt_toolkit import prompt
import traceback
from neo.Implementations.Wallets.peewee.UserWallet import UserWallet
from neocore.KeyPair import KeyPair
import bitcoin
from neocore.Cryptography.ECCurve import ECDSA
from neocore.Cryptography.Crypto import Crypto
import binascii
from threading import RLock
from logzero import logger
from neo.Core.Blockchain import Blockchain
from neo.SmartContract.Contract import Contract as WalletContract
from neo.Implementations.Wallets.peewee.Models import Account, Address, Contract
from neocore.IO.BinaryWriter import BinaryWriter
from neo.IO.MemoryStream import StreamManager


class OnlyPublicKeyPair(KeyPair):
    def __init__(self, public_key):
        pubkey_points = bitcoin.decode_pubkey(binascii.unhexlify(public_key), 'bin')
        pubx = pubkey_points[0]
        puby = pubkey_points[1]
        edcsa = ECDSA.secp256r1()
        self.PublicKey = edcsa.Curve.point(pubx, puby)
        self.PublicKeyHash = Crypto.ToScriptHash(self.PublicKey.encode_point(True), unhex=True)


class OnlyPublicWallet(UserWallet):
    def __init__(self):
        self._path = 'test123'
        self.AddressVersion = 23
        self._lock = RLock()
        self._indexedDB = Blockchain.Default()
        self.BuildDatabase()


        self._keys = {}
        self._contracts = self.LoadContracts()
        for public in ['0294cd0a9e77f358f709e69d9375680b1eafe75373645192b5b251260f484577ea']:
            kp = OnlyPublicKeyPair(public)
            self._keys[kp.PublicKeyHash.ToBytes()] = kp
            contract = WalletContract.CreateSignatureContract(kp.PublicKey)
            if contract.ScriptHash.ToBytes() not in self._contracts.keys():
                self._contracts[contract.ScriptHash.ToBytes()] = contract
                sh = bytes(contract.ScriptHash.ToArray())
                address, created = Address.get_or_create(ScriptHash=sh)
                address.IsWatchOnly = False
                address.save()
                db_contract = Contract.create(RawData=contract.ToArray(),
                        ScriptHash=contract.ScriptHash.ToBytes(),
                        PublicKeyHash=contract.PublicKeyHash.ToBytes(),
                        Address=address,
                        Account=None
                )






        self.LoadNamedAddresses()
        self._watch_only = self.LoadWatchOnly()
        self._tokens = self.LoadNEP5Tokens()
        self._coins = self.LoadCoins()
        self.initialize_holds()
        try:
            self._current_height = int(self.LoadStoredData('Height'))
        except:
            print('setting height to 0')
            self._current_height = 0
            self.SaveStoredData('Height', self._current_height)

    def OnProcessNewBlock(self, block, added, changed, deleted):
        if not self._current_height % 1000:
            logger.info('wallet height %i' % self._current_height)
            logger.info('synced %s' % self.IsSynced)
        return super().OnProcessNewBlock(block, added, changed, deleted)

    def DecryptPrivateKey(self, *args):
        raise NotImplementedError

    def EncryptPrivateKey(self, *args):
        raise NotImplementedError

    def ChangePassword(self, *args):
        raise NotImplementedError


def construct(wallet, arguments):
        from_address = arguments['from']
        to_send = arguments['asset']
        address_to = arguments['to']
        amount = arguments['amount']

        user_tx_attributes = arguments.get('attrs', [])

        assetId = get_asset_id(wallet, to_send)

        if assetId is None:
            raise Exception("Asset id not found")

        scripthash_to = lookup_addr_str(wallet, address_to)
        if scripthash_to is None:
            raise Exception("invalid address")

        scripthash_from = None

        if from_address is not None:
            scripthash_from = lookup_addr_str(wallet, from_address)

        if type(assetId) is NEP5Token:
            raise Exception("cannot transfer token in this version")

        f8amount = Fixed8.TryParse(amount, require_positive=True)
        if f8amount is None:
            raise Exception("invalid amount format")

        if type(assetId) is UInt256 and f8amount.value % pow(10, 8 - Blockchain.Default().GetAssetState(assetId.ToBytes()).Precision) != 0:
            raise Exception("incorrect amount precision")

        fee = Fixed8.Zero()

        output = TransactionOutput(AssetId=assetId, Value=f8amount, script_hash=scripthash_to)
        tx = ContractTransaction(outputs=[output])
        ttx = wallet.MakeTransaction(tx=tx,
                                     fee=fee,
                                     from_addr=scripthash_from)


        if ttx is None:
            raise Exception("no funds")

        standard_contract = wallet.GetStandardAddress()

        if scripthash_from is not None:
            signer_contract = wallet.GetContract(scripthash_from)
        else:
            signer_contract = wallet.GetContract(standard_contract)

        if not signer_contract.IsMultiSigContract:

            data = standard_contract.Data
            tx.Attributes = [TransactionAttribute(usage=TransactionAttributeUsage.Script,
                                                  data=data)]

        # insert any additional user specified tx attributes
        tx.Attributes = tx.Attributes + user_tx_attributes


        context = ContractParametersContext(tx, isMultiSig=signer_contract.IsMultiSigContract)
       

        logger.info(context.ToJson())
        logger.info('*'*60)
        logger.info(tx.ToJson())
#        import pdb
#        pdb.set_trace()
        ms = StreamManager.GetStream()
        writer = BinaryWriter(ms)
        tx.Serialize(writer)
        ms.flush()
        tx = ms.ToArray()
        print(tx)
        return {'context': context.ToJson(), 'tx': tx.decode()}

'''
def parse_and_sign(prompter, wallet, jsn):

    try:
        context = ContractParametersContext.FromJson(jsn)
        if context is None:
            print("Failed to parse JSON")
            return

        wallet.Sign(context)

        if context.Completed:

            print("Signature complete, relaying...")

            tx = context.Verifiable
            tx.scripts = context.GetScripts()

            wallet.SaveTransaction(tx)

            print("will send tx: %s " % json.dumps(tx.ToJson(), indent=4))

            relayed = NodeLeader.Instance().Relay(tx)

            if relayed:
                print("Relayed Tx: %s " % tx.Hash.ToString())
            else:
                print("Could not relay tx %s " % tx.Hash.ToString())
            return
        else:
            print("Transaction initiated, but the signature is incomplete")
            print(json.dumps(context.ToJson(), separators=(',', ':')))
            return

    except Exception as e:
        print("could not send: %s " % e)
        traceback.print_stack()
        traceback.print_exc()
'''
