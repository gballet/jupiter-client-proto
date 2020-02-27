extern crate account;
extern crate clap;
extern crate multiproof_rs;
extern crate rlp;
extern crate rusqlite;

use account::Account;
use clap::{App, Arg, SubCommand};
use multiproof_rs::{make_multiproof, ByteKey, Multiproof, NibbleKey, Node, ProofToTree, Tree};
use rusqlite::{Connection, Row, NO_PARAMS};

/// Represents a layer-2 transaction.
#[derive(Debug)]
struct Tx {
    from: NibbleKey,
    to: NibbleKey,
    nonce: u64,
    value: u64,
    call: u32, // Txs have only one instruction in this model, and it's a "call"
}

impl rlp::Encodable for Tx {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream
            .begin_unbounded_list()
            .append(&self.from)
            .append(&self.to)
            .append(&self.nonce)
            .append(&self.value)
            .append(&self.call)
            .finalize_unbounded_list();
    }
}

impl rlp::Decodable for Tx {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Tx {
            from: NibbleKey::from(rlp.val_at::<Vec<u8>>(0)?),
            to: NibbleKey::from(rlp.val_at::<Vec<u8>>(1)?),
            nonce: rlp.val_at(2)?,
            value: rlp.val_at(3)?,
            call: rlp.val_at(4)?,
        })
    }
}

/// Represents the data that should be encoded inside a layer one `data` field.
#[derive(Debug)]
struct TxData {
    proof: Multiproof,
    txs: Vec<Tx>,
    signature: Vec<u8>,
}

impl rlp::Encodable for TxData {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream
            .begin_unbounded_list()
            .append(&self.proof)
            .append_list(&self.txs)
            .append(&self.signature)
            .finalize_unbounded_list();
    }
}

impl rlp::Decodable for TxData {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(TxData {
            proof: rlp.val_at::<Multiproof>(0)?,
            txs: rlp.list_at(1)?,
            signature: rlp.val_at::<Vec<u8>>(2)?,
        })
    }
}

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
    db.execute("UPDATE root SET hash = ?1", hash)?;
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

fn extract_key(row: &Row) -> rusqlite::Result<(NibbleKey, Vec<u8>)> {
    let bkey = row.get::<_, Vec<u8>>(0)?;
    let k = NibbleKey::from(bkey);
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

fn main() -> rusqlite::Result<()> {
    let matches = App::new("jupiter-client")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::with_name("db").help("path to the database file"))
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
                        .help("signed transaction data"),
                ),
        )
        .get_matches();

    // Start with initializing the leaf DB
    let dbfilename = matches.value_of("db").unwrap_or("leaves.db");

    let db = initdb(dbfilename)?;

    match matches.subcommand() {
        ("join", Some(submatches)) => {
            let mut trie = rebuild_trie(&db).unwrap();
            let tx_value = submatches
                .value_of("value")
                .unwrap()
                .parse::<u64>()
                .unwrap();

            // TODO DRY
            let sender_addr = NibbleKey::from(ByteKey::from(
                hex::decode(submatches.value_of("addr").unwrap()).unwrap(),
            ));
            if trie.has_key(&sender_addr) {
                panic!(format!(
                    "Can not create address {:?} as it already exists",
                    sender_addr
                ));
            }

            // Proof that the account isn't already in the trie.
            let proof = make_multiproof(&trie, vec![sender_addr.clone()]).unwrap();

            let account = Account::Existing(sender_addr.clone(), 0, tx_value, vec![], true);
            trie.insert(&sender_addr, rlp::encode(&account)).unwrap();

            let layer2tx = Tx {
                value: tx_value,
                from: NibbleKey::from(
                    hex::decode("0000000000000000000000000000000000000000000000000000000000")
                        .unwrap(),
                ),
                to: sender_addr.clone(),
                call: 0,
                nonce: 0,
            };
            let txdata = TxData {
                proof,
                txs: vec![layer2tx],
                signature: vec![],
            };

            println!("New root: {:?}", trie.hash());
            println!("Transaction data: {:?}", txdata);
            println!("Encoded data: {}", hex::encode(rlp::encode(&txdata)));
        }
        ("sendtx", Some(submatches)) => {
            // Extract tx information
            let tx_value = submatches
                .value_of("value")
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap();

            let mut trie = rebuild_trie(&db).unwrap();

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

            // Serialize the updated sender account
            let next_saccount = match saccount {
                Account::Existing(_, _, ref mut balance, _, _) => {
                    // Check that the sender's value is lower than the sending account's
                    // balance.
                    if (*balance as u64) < tx_value {
                        panic!(format!("Account {:?} only has a balance of {}, which is lower than the requested {}", sender.0, balance, tx_value))
                    }


                    *balance -= tx_value;
                    rlp::encode(&saccount)
                }
                Account::Empty => panic!(format!(
                    "Attempting to send a transaction from empty account {:?}",
                    sender.0
                )),
            };

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

            // Serialize the updated recipient account
            let next_raccount = match raccount {
                Account::Existing(_, _, ref mut balance, _, _) => {

                    *balance += tx_value;
                    rlp::encode(&saccount)
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

            // Update the trie, generate the proof and calculate the root and add
            // it to the database.
            trie.insert(&sender.0, next_saccount).unwrap();
            trie.insert(&receiver.0, next_raccount).unwrap();
            let proof = make_multiproof(&trie, vec![sender.0.clone(), receiver.0.clone()]).unwrap();
            let final_hash = trie.hash();

            let layer2tx = Tx {
                value: tx_value,
                from: sender.0,
                to: receiver.0,
                call: 0,
                nonce: 0, // XXX saccount.nonce
            };
            println!(
                "Proof: {:?}\nHash: {:?}",
                TxData {
                    proof,
                    txs: vec![layer2tx],
                    signature: vec![]
                },
                final_hash
            );
        }
        ("apply", Some(submatches)) => {
            let txdata: TxData =
                rlp::decode(&hex::decode(submatches.value_of("data").unwrap()).unwrap()).unwrap();
            let mut trie: Node = txdata.proof.rebuild().unwrap();
            let root = get_root(&db);
            if root != trie.hash() {
                panic!("Invalid root hash {:?}", trie.hash());
            }

            for tx in txdata.txs {
                if tx.from != sender {
                    panic!(format!(
                        "Invalid transaction: from={:?} != to={:?}",
                        tx.from, sender
                    ));
                }

                if !trie.has_key(&tx.from) {
                    panic!(format!("Account isn't present in trie: {:?}", tx.from));
                }

                let sleaf = match trie[&tx.from] {
                    Node::Leaf(k, v) => v,
                    _ => panic!(format!("Address {:?} doesn't point to a leaf", tx.from)),
                };
                let sacc = match rlp::decode::<Account>(&sleaf).unwrap() {
                    sa @ Account::Existing(_, _, ref mut val, _, _) => {
                        *val -= tx.value;
                        sa
                    }
                    _ => panic!("Sender account is an empty account!"),
                };

                let racc = if !trie.has_key(&tx.to) {
                    match trie[&tx.to] {
                        Node::Leaf(k, v) => rlp::decode(&v).unwrap(),
                        _ => panic!(format!("Address {:?} doesn't point to a leaf", tx.to)),
                    }
                } else {
                    Account::Existing(tx.to, 0, tx.value, vec![], false)
                };

                db.execute(
                    "UPDATE hash WHERE key = ?1 SET value = ?2;",
                    vec![(tx.to, rlp::encode(&racc))],
                );

                db.execute(
                    "UPDATE hash WHERE key = ?1 SET value = ?2;",
                    vec![(tx.from, rlp::encode(&sacc))],
                );

                trie.insert(&tx.from, rlp::encode(&sacc)).unwrap();
                trie.insert(&tx.to, rlp::encode(&racc)).unwrap();
            }

            update_root(&db, trie.hash());
        }
        _ => panic!("Not implemented yet"),
    }

    Ok(())
}
