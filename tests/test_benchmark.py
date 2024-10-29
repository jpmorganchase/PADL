"""Instructions:
in order to run this example. Two services need to be up.
1. run: python cloud_server/python_storage/serv.py
(this service is a simple storage for the proofs and archive of the transactions)
2. run an evm node. Ideally run on Geth node. For simplicity, you can also test on a slow ganache-cli with the following launch command line:
    ganache-cli --account='0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63,100000000000000000000000' --account='0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be64,100000000000000000000000' --gasLimit=9999999999999999999999999 --chain.
vmErrorsOnRPCResponse=true"""

from unittest import TestCase

class TestLocal(TestCase):
    def test_benchmark_local(self): 
        import pyledger.examples.padl_local as padl_local
        try:
            padl_local.main()
        except Exception as error:
            print('error', error)

    def test_benchmark_evm(self): 
        import pyledger.examples.padl_evm as padl_evm
        try:
            padl_evm.main()
        except Exception as error:
            print('error', error)

