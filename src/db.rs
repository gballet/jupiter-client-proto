use super::JupiterError;
use jupiter_account::Account;
use multiproof_rs::{ByteKey, Hashable, NibbleKey, Node, Tree};
use rusqlite::{Connection, Row, NO_PARAMS};

pub(super) fn initdb(dbfilename: &str) -> Result<Connection, JupiterError> {
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

pub(super) fn get_root(db: &Connection) -> Vec<u8> {
    let h: Vec<u8> = db
        .query_row("select hash FROM root;", NO_PARAMS, |row| {
            Ok(row.get::<_, Vec<u8>>(0)?)
        })
        .unwrap();
    h
}

pub(super) fn update_root(db: &Connection, hash: Vec<u8>) -> rusqlite::Result<()> {
    println!("Setting trie root to {:?}", hex::encode(hash.clone()));
    db.execute(
        format!("UPDATE root SET hash = X'{}'", hex::encode(hash)).as_str(),
        NO_PARAMS,
    )?;
    Ok(())
}

pub(super) fn has_root(db: &Connection) -> bool {
    let count: u32 = db
        .query_row("select count(*) FROM root;", NO_PARAMS, |row| {
            Ok(row.get(0)?)
        })
        .unwrap();
    count > 0
}

pub(super) fn update_leaf(
    db: &Connection,
    key: NibbleKey,
    value: Vec<u8>,
) -> rusqlite::Result<usize> {
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

pub(super) fn insert_leaf(
    db: &Connection,
    key: NibbleKey,
    value: Vec<u8>,
) -> rusqlite::Result<usize> {
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

pub(super) fn log_tx(
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

pub(super) fn extract_key(row: &Row) -> rusqlite::Result<(NibbleKey, Vec<u8>)> {
    let bkey = row.get::<_, Vec<u8>>(0)?;
    let k: NibbleKey = NibbleKey::from(ByteKey::from(bkey));
    let v: Vec<u8> = row.get(1)?;
    Ok((k, v))
}

pub(super) fn rebuild_trie(db: &Connection) -> rusqlite::Result<Node> {
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

pub(super) fn get_account(db: &Connection, addr: &str) -> rusqlite::Result<Account> {
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
