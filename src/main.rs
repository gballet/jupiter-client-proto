extern crate clap;
extern crate jupiter_account;
extern crate multiproof_rs;
extern crate rand;
extern crate rlp;
extern crate rusqlite;
extern crate secp256k1;
extern crate sha3;

mod db;

use clap::{App, Arg, SubCommand};
use db::*;
use jupiter_account::{Account, Tx, TxData};
use multiproof_rs::{make_multiproof, ByteKey, Hashable, NibbleKey, Node, ProofToTree, Tree};
use rand::{thread_rng, Rng};
use rusqlite::NO_PARAMS;
use secp256k1::{recover as secp256k1_recover, sign as secp256k1_sign, Message, SecretKey};
use sha3::{Digest, Keccak256};

#[derive(Debug)]
struct JupiterError(String);

impl std::fmt::Display for JupiterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<rusqlite::Error> for JupiterError {
    fn from(re: rusqlite::Error) -> Self {
        JupiterError(format!("{}", re))
    }
}

impl From<&str> for JupiterError {
    fn from(s: &str) -> Self {
        JupiterError(format!("{}", s))
    }
}

fn main() -> Result<(), JupiterError> {
    let matches = App::new("jupiter-client")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::with_name("db").help("path to the database file"))
        .subcommand(
            SubCommand::with_name("keygen").about("generate a new account with its private key"),
        )
        .subcommand(
            SubCommand::with_name("join")
                .about("creates an signed tx to fund the layer 2 account")
                .arg(
                    Arg::with_name("skey")
                        .short("s")
                        .takes_value(true)
                        .required(true)
                        .help("the private key of the account to create"),
                )
                .arg(
                    Arg::with_name("value")
                        .takes_value(true)
                        .short("v")
                        .required(true)
                        .help("tx's value"),
                ),
        )
        .subcommand(
            SubCommand::with_name("sendtx")
                .about("creates an unsigned tx to send value")
                .arg(
                    Arg::with_name("from")
                        .short("f")
                        .takes_value(true)
                        .required(true)
                        .help("tx's sender address"),
                )
                .arg(
                    Arg::with_name("to")
                        .short("t")
                        .takes_value(true)
                        .required(true)
                        .help("tx's recipient address"),
                )
                .arg(
                    Arg::with_name("value")
                        .takes_value(true)
                        .short("v")
                        .required(true)
                        .help("tx's value"),
                )
                .arg(
                    Arg::with_name("signature")
                        .short("s")
                        .takes_value(true)
                        .help("tx's signature = sender's signature"),
                ),
        )
        .subcommand(
            SubCommand::with_name("embed")
                .about("embed a signed tx into an ethereum tx")
                .arg(
                    Arg::with_name("data")
                        .short("d")
                        .help("signed transaction data"),
                ),
        )
        .subcommand(
            SubCommand::with_name("apply")
                .about("run the transaction and update the database")
                .arg(
                    Arg::with_name("data")
                        .short("d")
                        .takes_value(true)
                        .required(true)
                        .help("signed transaction data"),
                )
                .arg(
                    Arg::with_name("sender")
                        .short("s")
                        .takes_value(true)
                        .required(true)
                        .help("address of the sender"),
                ),
        )
        .subcommand(
            SubCommand::with_name("accdmp")
                .about("dump the content of an account")
                .arg(
                    Arg::with_name("addr")
                        .short("a")
                        .takes_value(true)
                        .required(true)
                        .help("address of the account"),
                ),
        )
        .subcommand(
            SubCommand::with_name("merge")
                .about("merge two transactions in one")
                .arg(
                    Arg::with_name("data")
                        .short("d")
                        .takes_value(true)
                        .multiple(true)
                        .required(true)
                        .help("txdata to merge"),
                ),
        )
        .get_matches();

    // Start with initializing the leaf DB
    let dbfilename = matches.value_of("db").unwrap_or("leaves.db");

    let db = initdb(dbfilename)?;
    let mut trie = rebuild_trie(&db).unwrap();

    match matches.subcommand() {
        ("join", Some(submatches)) => {
            let tx_value = submatches
                .value_of("value")
                .unwrap()
                .parse::<u64>()
                .unwrap();

            // TODO DRY
            let keydata = hex::decode(submatches.value_of("skey").unwrap()).unwrap();
            let skey = SecretKey::parse_slice(&keydata[..]).unwrap();
            let mut sender = Account::from(&skey);
            if let Account::Existing(ref addr, _, ref mut balance, _, _) = sender {
                if trie.has_key(&addr) {
                    panic!(format!(
                        "Can not create address {:?} as it already exists",
                        addr
                    ));
                }
                *balance = tx_value;

                // Proof that the account isn't already in the trie.
                let proof = make_multiproof(&trie, vec![addr.clone()]).unwrap();

                trie.insert(&addr, rlp::encode(&sender)).unwrap();

                let mut layer2tx = Tx {
                    value: tx_value,
                    from: NibbleKey::from(ByteKey::from(
                        hex::decode(
                            "0000000000000000000000000000000000000000000000000000000000000000",
                        )
                        .unwrap(),
                    )),
                    data: vec![],
                    to: addr.clone(),
                    call: 0,
                    nonce: 0,
                    signature: vec![0u8; 65],
                };
                let mut key = [0u8; 32];
                key.copy_from_slice(&keydata[..32]);
                layer2tx.sign(&key);
                let txdata = TxData {
                    proof,
                    txs: vec![layer2tx],
                };

                println!("New root: {:?}", trie.hash());
                println!("Transaction data: {:?}", txdata);
                println!("Encoded data: {}", hex::encode(rlp::encode(&txdata)));

                db.execute(
                format!(
                    "INSERT INTO logs (type, sender, recipient, data) VALUES ('{}', '{}', '{}', X'{}');",
                    "join",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    hex::encode::<Vec<u8>>(ByteKey::from(addr.clone()).into()),
                    hex::encode(rlp::encode(&txdata))
                )
                .as_str(),
                NO_PARAMS,
            )?;
            } else {
                panic!("Could not create account")
            }
        }
        ("sendtx", Some(submatches)) => {
            // Extract tx information
            let tx_value = submatches
                .value_of("value")
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap();

            // Extract sender information
            let sender_addr: &str = submatches.value_of("from").unwrap();
            let sender: (NibbleKey, Vec<u8>) = db.query_row(
                "SELECT key, value FROM leaves WHERE key = ?1;",
                hex::decode(sender_addr),
                extract_key,
            )?;
            if !trie.has_key(&sender.0) {
                panic!(format!("Could not find sender address {:?}", sender));
            }
            let mut saccount: Account = rlp::decode(&sender.1).unwrap();

            // Extract recipient information
            let receiver_addr: &str = submatches.value_of("to").unwrap();
            let receiver: (NibbleKey, Vec<u8>) = db.query_row(
                "SELECT key, value FROM leaves WHERE key = ?1;",
                hex::decode(receiver_addr),
                extract_key,
            )?;
            if !trie.has_key(&receiver.0) {
                panic!(format!("Could not find receiver address {:?}", receiver));
            }
            let mut raccount: Account = rlp::decode(&receiver.1).unwrap();

            // Build the proof of the current state
            let proof = make_multiproof(&trie, vec![sender.0.clone(), receiver.0.clone()]).unwrap();

            // Serialize the updated sender account
            let updated_saccount = match saccount {
                Account::Existing(_, ref mut nonce, ref mut balance, _, _) => {
                    // Check that the sender's value is lower than the sending account's
                    // balance.
                    if (*balance as u64) < tx_value {
                        panic!(format!("Account {:?} only has a balance of {}, which is lower than the requested {}", sender.0, balance, tx_value))
                    }

                    *nonce += 1;

                    *balance -= tx_value;
                    rlp::encode(&saccount)
                }
                Account::Empty => panic!(format!(
                    "Attempting to send a transaction from empty account {:?}",
                    sender.0
                )),
            };

            // Serialize the updated recipient account
            let updated_raccount = match raccount {
                Account::Existing(_, _, ref mut balance, _, _) => {
                    *balance += tx_value;
                    rlp::encode(&raccount)
                }
                Account::Empty => {
                    // Sending to a non-existing account, create it
                    rlp::encode(&Account::Existing(
                        receiver.0.clone(),
                        0,
                        tx_value,
                        vec![],
                        vec![],
                    ))
                }
            };

            // Update values, and calculate the root
            trie.insert(&sender.0, updated_saccount).unwrap();
            trie.insert(&receiver.0, updated_raccount).unwrap();
            let final_hash = trie.hash();

            let layer2tx = Tx {
                value: tx_value,
                from: sender.0,
                to: receiver.0,
                call: 0,
                nonce: saccount.nonce(),
                signature: vec![0u8; 65],
                data: vec![],
            };
            let txdata = TxData {
                proof,
                txs: vec![layer2tx],
            };

            // Do NOT update the db: this transaction might not be accepted
            println!("Proof: {:?}\nHash: {:?}", txdata, final_hash);
            println!("Encoded data: {}", hex::encode(rlp::encode(&txdata)));

            db.execute(
                format!(
                    "INSERT INTO logs (type, sender, recipient, data) VALUES ('{}', '{}', '{}', X'{}');",
                    "sendtx",
                    submatches.value_of("from").unwrap(),
                    submatches.value_of("to").unwrap(),
                    hex::encode(rlp::encode(&txdata))
                )
                .as_str(),
                NO_PARAMS,
            )?;
        }
        ("apply", Some(submatches)) => {
            let input_data = hex::decode(submatches.value_of("data").unwrap()).unwrap();
            jupiter_contract::eth::set_calldata(input_data);

            let root = get_root(&db);
            jupiter_contract::eth::set_storage_root(root);

            jupiter_contract::contract_main()?;

            let mut newroot = vec![0u8; 32];
            jupiter_contract::eth::get_storage_root(&mut newroot);
            update_root(&db, newroot)?;
        }
        ("accdmp", Some(submatches)) => {
            let addr = submatches.value_of("addr").unwrap();
            let account = get_account(&db, addr).unwrap();
            println!("Account: {:?}", account);
        }
        ("merge", Some(submatches)) => {
            if let Some(txdata_list) = submatches.values_of("data") {
                let mut all_txs = vec![];
                let original_trie = trie.clone();
                let mut addrs = vec![];
                for txdata_hex in txdata_list {
                    let txdata: TxData = rlp::decode(&hex::decode(txdata_hex).unwrap()).unwrap();
                    let prooftrie: Node = txdata.proof.rebuild().unwrap();
                    let root = get_root(&db);
                    if prooftrie.hash() != root {
                        panic!("invalid root in data");
                    }

                    for tx in txdata.txs {
                        addrs.push(tx.from.clone());
                        addrs.push(tx.to.clone());

                        all_txs.push(tx);
                    }
                }

                let proof = make_multiproof(&original_trie, addrs).unwrap();

                let txdata = TxData {
                    proof,
                    txs: all_txs,
                };

                println!("New root: {:?}", trie.hash());
                println!("Transaction data: {:?}", txdata);
                println!("Encoded data: {}", hex::encode(rlp::encode(&txdata)));
            } else {
                panic!("no tx data provided")
            }
        }
        ("keygen", _) => {
            let mut rng = thread_rng();
            let mut skdata = [0u8; 32];
            rng.fill(&mut skdata);
            let sk = SecretKey::parse(&skdata).unwrap();
            let msg = Message::parse_slice(&[0x55u8; 32]).unwrap();
            let (sig, recid) = secp256k1_sign(&msg, &sk);
            let pk = secp256k1_recover(&msg, &sig, &recid).unwrap();
            let mut keccak256 = Keccak256::new();
            keccak256.input(&pk.serialize()[..]);
            let addr = keccak256.result_reset()[..20].to_vec();

            println!("addr={:?}", hex::encode(addr));
            println!("privkey={:?}", hex::encode(sk.serialize()));
        }
        _ => panic!("Not implemented yet"),
    }

    Ok(())
}
