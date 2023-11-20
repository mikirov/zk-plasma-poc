
use dep::noir_biguint;
use dep::ecrecover::secp256k1;
use dep::std;

// max number of UTXOs in the set. Represented by u8. Make it larger if needed but will require more memory.
//NOTE: if you modify this value, make it a power of 2 and modify Transaction struct with type that fits this value as well.
global MAX_UTXO_COUNT = 4294967296; // u32
global MAX_TRANSACTION_COUNT = 10;
global MAX_INPUT_COUNT = 5;
global MAX_OUTPUT_COUNT = 5;
global INPUT_SIZE = 20; // 4 * MAX_INPUT_COUNT;
global OUPTUT_SIZE = 520;// 104 * MAX_OUTPUT_COUNT;
global UTXO_SIZE = 542; // INPUT_SIZE + OUTPUT_SIZE + 2;
//TODO: UTXOs should have pubKey associated that is allowed to spend the UTXO
// outputs should have a value + pubKey associated with it

struct Output {
    value: [u8; 32], // represents u256 value in EVM
    erc20_address: [u8; 20], // represents address of ERC20 token contract. Ised as an ID. If it's null we can consider the transfer to be ETH transfer
    spender_pub_key_x: [u8; 32],
    spender_pub_key_y: [u8; 32],
    nonce: u64
}

struct UTXO {
    input_utxo_indexes: [u32; MAX_INPUT_COUNT], // UTXO size is limited to 32 bits for the sake of not running out of RAM
    input_count: u8,
    outputs: [Output; MAX_OUTPUT_COUNT],
    output_count: u8,
}

impl UTXO {
    fn to_bytes(self: Self) -> [u8; UTXO_SIZE] {
        let mut res =  [0 as u8; UTXO_SIZE];
        let mut index = 0;

        for i in 0..MAX_INPUT_COUNT {
            let input_utxo_index = self.input_utxo_indexes[i] as u32;
            for j in 0..4 {
                let shift_amount: u32 = 24 - (j * 8) as u32;
                res[index] = ((input_utxo_index >> shift_amount) & 255) as u8;
                index += 1;
            }
        }

        res[index] = self.input_count;
        index += 1;

        for i in 0..MAX_OUTPUT_COUNT {
            for j in 0..32 {
                res[index] = self.outputs[i].value[j];
                index += 1;
            }
            for j in 0..32 {
                res[index] = self.outputs[i].spender_pub_key_x[j];
                index += 1;
            }
            for j in 0..32 {
                res[index] = self.outputs[i].spender_pub_key_y[j];
                index += 1;
            }
            for j in 0..8 {
                let shift_amount: u64 = 56 - (j * 8) as u64;
                res[index] = ((self.outputs[i].nonce >> shift_amount) & 255) as u8;
                index += 1;
            }
        }
        res[index] = self.output_count;
         
        res
    }

}

struct SignedTransaction {
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    transaction: UTXO
}

impl SignedTransaction {
    fn verify(self) -> bool {
        let transaction_bytes: [u8; UTXO_SIZE] = self.transaction.to_bytes();
        let hashed_transaction = std::hash::keccak256(transaction_bytes, UTXO_SIZE);
        let key = secp256k1::PubKey::from_xy(self.pub_key_x, self.pub_key_y);
        let res = key.verify_sig(self.signature, hashed_transaction);
        res
    }
}

//utxo_set_before and utxo_set_after are the sets of UTXOs before and after executing the transaction traces
// it is represented as merkle tree root and sibling path.
// The merkle tree must be append-only, elements are to be appended to the back at Nonce index.
// The nullifier tree will be append-only and should be used to proove UTXO has not been spent using merkle non-inclusion proof.
// nullifier
// Merkle tree of depth 32 should be enough to represent 4 billion UTXOs, enough to cover the next 27 years at 5 TPS at full usage.
// Nonce + nullifier tree should also checked against to ensure there is no replay attacks.
// see https://github.com/tomoima525/noir-merkle-root/tree/main for merkle inclusion proof
// path_indices - wheather or not the sibling value is on the left or right side of the branch
fn main(utxo_root_before: Field, path_indices: [Field; 32], siblings: [Field; 32], signed_transaction: SignedTransaction, merkle_root_after: [Output; MAX_UTXO_COUNT], latest_utxo_nonce: u64) {
    for i in 0..MAX_TRANSACTION_COUNT {

        assert(signed_transactions[i].verify());

        //then check inputs are available and required amount is available
        let mut total_value_inputs = noir_biguint::BigUint56::zero();
        for j in 0..MAX_INPUT_COUNT {
            let input_utxo_index = signed_transactions[i].transaction.input_utxo_indexes[j];
            // if value is non-zero at given slot then index is valid
            //TODO: how to do empty array check?
            assert(utxo_set_before[input_utxo_index].nonce != 0);

            //verify that the signer of the transaction is authorized to spend the utxo
            assert(utxo_set_before[input_utxo_index].spender_pub_key_x == signed_transactions[i].pub_key_x);
            assert(utxo_set_before[input_utxo_index].spender_pub_key_y == signed_transactions[i].pub_key_y);

            total_value_inputs = total_value_inputs.add(noir_biguint::BigUint56::from_bytes(utxo_set_before[input_utxo_index].value));
        }

        let mut total_value_outputs = noir_biguint::BigUint56::zero();
        for j in 0..MAX_OUTPUT_COUNT {
            let output = signed_transactions[i].transaction.outputs[j];
            total_value_outputs = total_value_outputs.add(noir_biguint::BigUint56::from_bytes(output.value));

            utxo_set_before[latest_utxo_nonce + j].value = total_value_outputs.to_bytes();
            //TODO: figure out output slot index in the resulting set
            assert(utxo_set_before[output_utxo_index] == 0);
        }

        //check resulting utxo set from params and computed are the same

        // assert(total_value_inputs.le(total_value_outputs));

    }

}

#[test]
fn test_main() {

}
