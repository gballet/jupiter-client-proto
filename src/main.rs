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
                        .help("tx's sender address"),
                )
                .arg(
                    Arg::with_name("to")
                        .short("t")
                        .help("tx's recipient address"),
                )
                .arg(
                    Arg::with_name("value")
                        .takes_value(true)
                        .short("v")
                        .help("tx's value"),
                )
                .arg(
                    Arg::with_name("nonce")
                        .takes_value(true)
                        .short("n")
                        .help("tx's nonce"),
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

            let account = Account::Existing(sender_addr.clone(), tx_value as u32, vec![], true);
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
            let proof = make_multiproof(&trie, vec![sender_addr]).unwrap();
            let txdata = TxData {
                proof,
                txs: vec![layer2tx],
                signature: vec![],
            };

            println!("New root: {:?}", trie.hash());
            println!("Transaction data: {:?}", txdata);
            println!("Encoded data: {:?}", rlp::encode(&txdata));
        }
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
        _ => panic!("Not implemented yet"),
    }

    Ok(())
}
