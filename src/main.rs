extern crate clap;
extern crate multiproof_rs;
extern crate rusqlite;

use multiproof_rs::{NibbleKey, Node, Tree};
use rusqlite::NO_PARAMS;
use rusqlite::{Connection, Result, Row};

use clap::{App, Arg, SubCommand};

fn initdb(dbfilename: &str) -> Result<Connection> {
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

fn has_root(db: &Connection) -> bool {
    let count: u32 = db
        .query_row("select count(*) FROM root;", NO_PARAMS, |row| {
            Ok(row.get(0)?)
        })
        .unwrap();
    count > 0
}

fn extract_key(row: &Row) -> Result<(NibbleKey, Vec<u8>)> {
    let bkey = row.get::<_, Vec<u8>>(0)?;
    let k = NibbleKey::from(bkey);
    let v: Vec<u8> = row.get(1)?;
    Ok((k, v))
}

fn rebuild_trie(db: &Connection) -> Result<Node> {
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

fn main() -> Result<()> {
    let matches = App::new("jupiter-client")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::with_name("db").help("path to the database file"))
        .subcommand(
            SubCommand::with_name("new")
                .about("craft a new, unsigned tx")
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
        ("new", Some(submatches)) => {}
        _ => panic!("Not implemented yet"),
    }

    Ok(())
}
