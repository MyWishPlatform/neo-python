from neo.Core.Blockchain import Blockchain
from neo.VM.ScriptBuilder import ScriptBuilder
from neo.SmartContract.ApplicationEngine import ApplicationEngine
from neo.SmartContract import TriggerType
from neo.SmartContract.StateMachine import StateMachine
from neo.Implementations.Blockchains.LevelDB.CachedScriptTable import CachedScriptTable
from neo.Core.TX.InvocationTransaction import InvocationTransaction
from neo.Core.State.AccountState import AccountState
from neo.Core.State.AssetState import AssetState
from neo.Core.State.ValidatorState import ValidatorState
from neo.Core.State.ContractState import ContractState
from neo.Core.State.StorageItem import StorageItem
from neo.Implementations.Blockchains.LevelDB.DBPrefix import DBPrefix
from neo.Blockchain import GetBlockchain
from neo.Implementations.Blockchains.LevelDB.DBCollection import DBCollection
from neo.Core.TX.Transaction import TransactionOutput, ContractTransaction
from neo.Core.TX.TransactionAttribute import TransactionAttribute, TransactionAttributeUsage
from neo.SmartContract.ContractParameterContext import ContractParametersContext
from neo.SmartContract.ContractParameter import ContractParameter
from neo.Network.NodeLeader import NodeLeader
from neo.Prompt.Utils import get_arg, get_from_addr, get_asset_id, lookup_addr_str, get_tx_attr_from_args
from neo.Prompt.Commands.Tokens import do_token_transfer, amount_from_string
from neo.Prompt.Commands.LoadSmartContract import generate_deploy_script
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
from neo.Prompt.Utils import parse_param
from neo.Core.FunctionCode import FunctionCode
from neo.Core.State.ContractState import ContractPropertyState
from neo.Prompt.Commands.Invoke import InvokeContract, TestInvokeContract, test_invoke

class OnlyPublicKeyPair(KeyPair):
    def __init__(self, public_key):
        pubkey_points = bitcoin.decode_pubkey(binascii.unhexlify(public_key), 'bin')
        pubx = pubkey_points[0]
        puby = pubkey_points[1]
        edcsa = ECDSA.secp256r1()
        self.PublicKey = edcsa.Curve.point(pubx, puby)
        self.PublicKeyHash = Crypto.ToScriptHash(self.PublicKey.encode_point(True), unhex=True)


class OnlyPublicWallet(UserWallet):
    def __init__(self, public):
        self._path = 'test123'
        self.AddressVersion = 23
        self._lock = RLock()
        self._indexedDB = Blockchain.Default()
        self.BuildDatabase()


        self._keys = {}
        self._contracts = self.LoadContracts()
#        for public in ['0294cd0a9e77f358f709e69d9375680b1eafe75373645192b5b251260f484577ea']:
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

def construct_send_tx(wallet, arguments):
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
        binary_tx = ms.ToArray()
        print(tx)
        return {'context': context.ToJson(), 'tx': binary_tx.decode()}

class JsonRpcError(Exception):
    message = None
    code = None

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message



def construct_deploy_tx(wallet, params):
    params = params[0]
    from_addr = params['from_addr']
    # load_smart_contract
    contract_params = bytearray(binascii.unhexlify(params['contract_params']))
    return_type = bytearray(binascii.unhexlify(params['return_type']))
    
    contract_properties = 0
    if params.get('needs_storage', True):
        contract_properties += ContractPropertyState.HasStorage
    if params.get('needs_dynamic_invoke', False):
        contract_properties += ContractPropertyState.HasDynamicInvoke

    script = binascii.unhexlify(params['bin'])

    function_code = FunctionCode(
            script = script,
            param_list = contract_params,
            return_type = return_type,
            contract_properties = contract_properties,
    )

    if Blockchain.Default().GetContract(function_code.ScriptHash().To0xString()):
        raise Exception('contract already exists')

    # GatherContractDetails
    details = params['details']
    name = details['name']
    version = details['version']
    author = details['author']
    email = details['email']
    description = details['description']

    contract_script = generate_deploy_script(
            function_code.Script,
            name,
            version,
            author,
            email,
            description,
            function_code.ContractProperties,
            function_code.ReturnType,
            function_code.ParameterList,
    )

    # test_invoke    
    bc = GetBlockchain()
    sn = bc._db.snapshot()
    accounts = DBCollection(bc._db, sn, DBPrefix.ST_Account, AccountState)
    assets = DBCollection(bc._db, sn, DBPrefix.ST_Asset, AssetState)
    validators = DBCollection(bc._db, sn, DBPrefix.ST_Validator, ValidatorState)
    contracts = DBCollection(bc._db, sn, DBPrefix.ST_Contract, ContractState)
    storages = DBCollection(bc._db, sn, DBPrefix.ST_Storage, StorageItem)


    tx = InvocationTransaction()
    tx.outputs = []
    tx.inputs = []
    tx.Version = 1
    tx.scripts = []
    tx.Script = binascii.unhexlify(contract_script)

    script_table = CachedScriptTable(contracts)
    service = StateMachine(accounts, validators, assets, contracts, storages, None)
    contract = wallet.GetDefaultContract()
    tx.Attributes = [TransactionAttribute(usage=TransactionAttributeUsage.Script, data=Crypto.ToScriptHash(contract.Script, unhex=False).Data)]
    tx = wallet.MakeTransaction(tx=tx)

    engine = ApplicationEngine(
            trigger_type=TriggerType.Application,
            container=tx,
            table=script_table,
            service=service,
            gas=tx.Gas,
            testMode=True
    )   
    engine.LoadScript(tx.Script, False)
    success = engine.Execute()
    if not success:
        raise Exception('exec failed')
    
    service.ExecutionCompleted(engine, success)

    consumed = engine.GasConsumed() - Fixed8.FromDecimal(10)
    consumed = consumed.Ceil()

    net_fee = None
    tx_gas = None

    if consumed <= Fixed8.Zero():
        net_fee = Fixed8.FromDecimal(.0001)
        tx_gas = Fixed8.Zero()
    else:
        tx_gas = consumed
        net_fee = Fixed8.Zero()
    tx.Gas = tx_gas
    tx.outputs = []
    tx.Attributes = []

    # InvokeContract
    from_addr = lookup_addr_str(wallet, from_addr)
    tx = wallet.MakeTransaction(tx=tx, fee=net_fee, use_standard=True, from_addr=from_addr)
    if tx is None:
        raise Exception("no gas")


    context = ContractParametersContext(tx)
    ms = StreamManager.GetStream()
    writer = BinaryWriter(ms)
    tx.Serialize(writer)
    ms.flush()
    binary_tx = ms.ToArray()
    return {'context': context.ToJson(), 'tx': binary_tx.decode(), 'hash': function_code.ScriptHash().To0xString()}



def construct_invoke_tx(wallet, params):
    params = params[0]
    from_addr = params['from_addr']
    
    BC = GetBlockchain()

    contract = BC.GetContract(params['addr'])

    if not contract:
        raise Exception('no such contract')

    neo_to_attach = params.get('neo_to_attach', 0)
    gas_to_attach = params.get('gas_to_attach', 0)

    sb = ScriptBuilder()
    contract_parameters = [ContractParameter.FromJson(p) for p in params['contract_params']]
    sb.EmitAppCallWithJsonArgs(contract.Code.ScriptHash(), contract_parameters)
    
    invoke_script = sb.ToArray()

    outputs = []

    if neo_to_attach:

        output = TransactionOutput(AssetId=Blockchain.SystemShare().Hash,
                Value=neo_to_attach,
                script_hash=contract.Code.ScriptHash(),
        )
        outputs.append(output)

    if gas_to_attach:

        output = TransactionOutput(AssetId=Blockchain.SystemCoin().Hash,
                Value=gas_to_attach,
                script_hash=contract.Code.ScriptHash(),
        )

        outputs.append(output)

    bc = GetBlockchain()
    sn = bc._db.snapshot()
    accounts = DBCollection(bc._db, sn, DBPrefix.ST_Account, AccountState)
    assets = DBCollection(bc._db, sn, DBPrefix.ST_Asset, AssetState)
    validators = DBCollection(bc._db, sn, DBPrefix.ST_Validator, ValidatorState)
    contracts = DBCollection(bc._db, sn, DBPrefix.ST_Contract, ContractState)
    storages = DBCollection(bc._db, sn, DBPrefix.ST_Storage, StorageItem)


    tx = InvocationTransaction()
    tx.outputs = outputs
    tx.inputs = []
    tx.Version = 1
    tx.scripts = []
    tx.Script = binascii.unhexlify(invoke_script)

    script_table = CachedScriptTable(contracts)
    service = StateMachine(accounts, validators, assets, contracts, storages, None)
    contract = wallet.GetDefaultContract()
    tx.Attributes = [TransactionAttribute(usage=TransactionAttributeUsage.Script, data=Crypto.ToScriptHash(contract.Script, unhex=False).Data)]
    tx = wallet.MakeTransaction(tx=tx)

    engine = ApplicationEngine(
            trigger_type=TriggerType.Application,
            container=tx,
            table=script_table,
            service=service,
            gas=tx.Gas,
            testMode=True
    )   
    engine.LoadScript(tx.Script, False)
    success = engine.Execute()
    if not success:
        raise Exception('exec failed')
    
    service.ExecutionCompleted(engine, success)

    consumed = engine.GasConsumed() - Fixed8.FromDecimal(10)
    consumed = consumed.Ceil()

    net_fee = None
    tx_gas = None

    if consumed <= Fixed8.Zero():
        net_fee = Fixed8.FromDecimal(.0001)
        tx_gas = Fixed8.Zero()
    else:
        tx_gas = consumed
        net_fee = Fixed8.Zero()
    tx.Gas = tx_gas
    tx.outputs = outputs
    tx.Attributes = []



    # InvokeContract
    from_addr = lookup_addr_str(wallet, from_addr)
    tx = wallet.MakeTransaction(tx=tx, fee=net_fee, use_standard=True, from_addr=from_addr)
    if tx is None:
        raise Exception("no gas")


    context = ContractParametersContext(tx)
    ms = StreamManager.GetStream()
    writer = BinaryWriter(ms)
    tx.Serialize(writer)
    ms.flush()
    binary_tx = ms.ToArray()
    return {'context': context.ToJson(), 'tx': binary_tx.decode()}
