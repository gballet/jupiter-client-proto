extern crate clap;
extern crate jupiter_account;
extern crate multiproof_rs;
extern crate rand;
extern crate rlp;
extern crate rusqlite;
extern crate secp256k1;
extern crate sha3;

use clap::{App, Arg, SubCommand};
use jupiter_account::{Account, Tx, TxData};
use multiproof_rs::{make_multiproof, ByteKey, NibbleKey, Node, ProofToTree, Tree};
use rand::{thread_rng, Rng};
use rusqlite::{Connection, Row, NO_PARAMS};
use secp256k1::{recover as secp256k1_recover, sign as secp256k1_sign, Message, SecretKey};
use sha3::{Digest, Keccak256};

fn initdb(dbfilename: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(dbfilename)?;

    conn.execute(
        "create table if not exists leaves(id integer primary key, key blob, value blob);",
        NO_PARAMS,
    )?;

    conn.execute("CREATE TABLE IF NOT EXISTS root(hash blob);", NO_PARAMS)?;

    let rootcount: u32 = conn.query_row("select count(*) FROM root;", NO_PARAMS, |row| {
        Ok(row.get(0)?)
    })?;
    if rootcount == 0 {
        let empty_root = Node::EmptySlot;
        conn.execute(
            format!(
                "INSERT INTO root (hash) values (X'{}')",
                hex::encode(empty_root.hash())
            )
            .as_str(),
            NO_PARAMS,
        )?;
    }

    conn.execute(
        "CREATE TABLE IF NOT EXISTS logs(id integer primary key, type string, sender blob, recipient blob, data blob);",
        NO_PARAMS,
    )?;

    Ok(conn)
}

fn get_root(db: &Connection) -> Vec<u8> {
    let h: Vec<u8> = db
        .query_row("select hash FROM root;", NO_PARAMS, |row| {
            Ok(row.get::<_, Vec<u8>>(0)?)
        })
        .unwrap();
    h
}

fn update_root(db: &Connection, hash: Vec<u8>) -> rusqlite::Result<()> {
    println!("Setting trie root to {:?}", hex::encode(hash.clone()));
    db.execute(
        format!("UPDATE root SET hash = X'{}'", hex::encode(hash)).as_str(),
        NO_PARAMS,
    )?;
    Ok(())
}

fn has_root(db: &Connection) -> bool {
    let count: u32 = db
        .query_row("select count(*) FROM root;", NO_PARAMS, |row| {
            Ok(row.get(0)?)
        })
        .unwrap();
    count > 0
}

fn update_leaf(db: &Connection, key: NibbleKey, value: Vec<u8>) -> rusqlite::Result<usize> {
    db.execute(
        format!(
            "UPDATE leaves SET value = X'{}' WHERE key = X'{}';",
            hex::encode(value),
            hex::encode::<Vec<u8>>(ByteKey::from(key).into()),
        )
        .as_str(),
        NO_PARAMS,
    )
}

fn insert_leaf(db: &Connection, key: NibbleKey, value: Vec<u8>) -> rusqlite::Result<usize> {
    db.execute(
        format!(
            "INSERT INTO leaves (key, value) VALUES (X'{}', X'{}');",
            hex::encode::<Vec<u8>>(ByteKey::from(key).into()),
            hex::encode(value),
        )
        .as_str(),
        NO_PARAMS,
    )
}

fn log_tx(
    db: &Connection,
    operation: &str,
    from: NibbleKey,
    to: NibbleKey,
    val: Vec<u8>,
) -> rusqlite::Result<usize> {
    db.execute(
        format!(
            "INSERT INTO logs (type, sender, recipient, data) VALUES ('{}', '{}', '{}', X'{}');",
            operation,
            hex::encode::<Vec<u8>>(ByteKey::from(from).into()),
            hex::encode::<Vec<u8>>(ByteKey::from(to).into()),
            hex::encode(val)
        )
        .as_str(),
        NO_PARAMS,
    )
}

fn extract_key(row: &Row) -> rusqlite::Result<(NibbleKey, Vec<u8>)> {
    let bkey = row.get::<_, Vec<u8>>(0)?;
    let k: NibbleKey = NibbleKey::from(ByteKey::from(bkey));
    let v: Vec<u8> = row.get(1)?;
    Ok((k, v))
}

fn rebuild_trie(db: &Connection) -> rusqlite::Result<Node> {
    let mut root = Node::EmptySlot;
    if has_root(db) {
        let mut stmt = db.prepare("SELECT key, value FROM leaves ORDER BY key;")?;
        let keyvals = stmt.query_map(NO_PARAMS, extract_key)?;

        for kvr in keyvals {
            let (key, val) = kvr?;
            root.insert(&key, val.to_vec()).unwrap();
        }
    }

    Ok(root)
}

fn get_account(db: &Connection, addr: &str) -> rusqlite::Result<Account> {
    if !has_root(db) {
        panic!("db has no root");
    }

    let val = db
        .query_row(
            format!("SELECT value FROM leaves WHERE key = X'{}'", addr).as_str(),
            NO_PARAMS,
            |row| row.get::<_, Vec<u8>>(0),
        )
        .unwrap_or_default();

    Ok(rlp::decode(&val).unwrap())
}

fn apply_tx(tx: &Tx, trie: &mut Node, sender: &NibbleKey) -> (bool, Vec<u8>, Vec<u8>) {
    let is_create = NibbleKey::from(ByteKey::from(
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
    )) == tx.from;

    // Note that anyone can create an account for someone else
    let sacc = if is_create {
        if trie.has_key(&tx.from) {
            panic!(format!(
                "Trying to create an account that is already present at address {:?}",
                tx.from
            ));
        }

        Account::Existing(tx.from.clone(), 0, tx.value, vec![], false)
    } else {
        if tx.from != *sender {
            panic!(format!(
                "Invalid transaction: from={:?} != sender={:?}",
                tx.from, sender
            ));
        }

        if !trie.has_key(&tx.from) {
            panic!(format!("Account isn't present in trie: {:?}", tx.from));
        }

        let sleaf = match &trie[&tx.from] {
            Node::Leaf(_, v) => v,
            _ => panic!(format!("Address {:?} doesn't point to a leaf", tx.from)),
        };
        let sacc = match rlp::decode::<Account>(&sleaf).unwrap() {
            Account::Existing(addr, n, val, code, state) => {
                Account::Existing(addr, n, val - tx.value, code, state)
            }
            _ => panic!("Sender account is an empty account!"),
        };

        trie.insert(&tx.from, rlp::encode(&sacc)).unwrap();

        sacc
    };

    // Check nonce
    if tx.nonce != sacc.nonce() {
        panic!("Invalid nonce");
    }

    let racc = if trie.has_key(&tx.to) {
        match &trie[&tx.to] {
            Node::Leaf(_, v) => {
                let mut acc: Account = rlp::decode(&v).unwrap();
                match acc {
                    Account::Existing(_, _, ref mut balance, _, _) => *balance += tx.value,
                    _ => panic!("proof is considering an existing account as non-existent"),
                }
                acc
            }
            _ => panic!(format!("Address {:?} doesn't point to a leaf", tx.to)),
        }
    } else {
        Account::Existing(tx.to.clone(), 0, tx.value, vec![], false)
    };
    trie.insert(&tx.to, rlp::encode(&racc)).unwrap();

    (is_create, rlp::encode(&sacc), rlp::encode(&racc))
}

fn main() -> rusqlite::Result<()> {
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
                .about("creates an unsigned tx to send value")
                .arg(
                    Arg::with_name("addr")
                        .short("a")
                        .takes_value(true)
                        .required(true)
                        .help("the account to create"),
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
            let a = hex::decode(submatches.value_of("addr").unwrap()).unwrap();
            let sender_addr = NibbleKey::from(ByteKey::from(a));
            if trie.has_key(&sender_addr) {
                panic!(format!(
                    "Can not create address {:?} as it already exists",
                    sender_addr
                ));
            }

            // Proof that the account isn't already in the trie.
            let proof = make_multiproof(&trie, vec![sender_addr.clone()]).unwrap();

            let account = Account::Existing(sender_addr.clone(), 0, tx_value, vec![], false);
            trie.insert(&sender_addr, rlp::encode(&account)).unwrap();

            let layer2tx = Tx {
                value: tx_value,
                from: NibbleKey::from(ByteKey::from(
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                        .unwrap(),
                )),
                to: sender_addr,
                call: 0,
                nonce: account.nonce(),
            };
            let txdata = TxData {
                proof,
                txs: vec![layer2tx],
                signature: vec![],
            };

            println!("New root: {:?}", trie.hash());
            println!("Transaction data: {:?}", txdata);
            println!("Encoded data: {}", hex::encode(rlp::encode(&txdata)));

            db.execute(
                format!(
                    "INSERT INTO logs (type, sender, recipient, data) VALUES ('{}', '{}', '{}', X'{}');",
                    "join",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    submatches.value_of("addr").unwrap(),
                    hex::encode(rlp::encode(&txdata))
                )
                .as_str(),
                NO_PARAMS,
            )?;
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
                        true,
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
            };
            let txdata = TxData {
                proof,
                txs: vec![layer2tx],
                signature: vec![],
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
            let txdata: TxData =
                rlp::decode(&hex::decode(submatches.value_of("data").unwrap()).unwrap()).unwrap();
            let prooftrie: Node = txdata.proof.rebuild().unwrap();
            let root = get_root(&db);
            if root != prooftrie.hash() {
                panic!("Invalid root hash {:?} != {:?}", trie.hash(), root);
            }
            assert_eq!(trie.hash(), prooftrie.hash());

            // Ideally, this code should recover the sender's address
            // from the tx's signature. This will not be handled at this
            // time so the command line value is currently trusted.
            let sender = NibbleKey::from(ByteKey::from(
                hex::decode(submatches.value_of("sender").unwrap()).unwrap(),
            ));

            for tx in txdata.txs {
                let (is_create, sacc, racc) = apply_tx(&tx, &mut trie, &sender);

                if !is_create {
                    update_leaf(&db, tx.to.clone(), racc)?;
                    update_leaf(&db, tx.from.clone(), sacc)?;
                } else {
                    insert_leaf(&db, tx.to.clone(), racc)?;
                }

                // Update the root at each successful tx, because it might
                // then fail. TODO make all these updates as a (db) transaction
                update_root(&db, trie.hash())?;

                let val = rlp::encode(&tx);
                log_tx(&db, "apply", tx.from, tx.to, val)?;
            }
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
                let mut senders = vec![];
                for txdata_hex in txdata_list {
                    let txdata: TxData = rlp::decode(&hex::decode(txdata_hex).unwrap()).unwrap();
                    let prooftrie: Node = txdata.proof.rebuild().unwrap();
                    let root = get_root(&db);
                    if prooftrie.hash() != root {
                        panic!("invalid root in data");
                    }

                    for tx in txdata.txs {
                        // Check the tx can be applied
                        // NOTE at the moment the sender is not checked,
                        // and this check will be removed in the furture
                        // because there is a need to get it from the tx
                        // signature
                        apply_tx(&tx, &mut trie, &tx.from);

                        senders.push(tx.from.clone());
                        all_txs.push(tx);
                    }
                }

                let proof = make_multiproof(&original_trie, senders).unwrap();

                let txdata = TxData {
                    proof,
                    txs: all_txs,
                    signature: vec![],
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
