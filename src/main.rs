extern crate clap;
extern crate rusqlite;

use rusqlite::NO_PARAMS;
use rusqlite::{Connection, Result};

use clap::{App, Arg, SubCommand};

fn initdb(dbfilename: &str) -> Result<Connection> {
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
        let empty_root =
            hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
        conn.execute("INSERT INTO root (hash) values (?1)", empty_root)?;
    }

    Ok(conn)
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
                .arg(Arg::with_name("value").short("v").help("tx's value"))
                .arg(Arg::with_name("nonce").short("n").help("tx's nonce"))
                .arg(
                    Arg::with_name("signature")
                        .short("s")
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
