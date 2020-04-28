[![CircleCI](https://circleci.com/gh/gballet/jupiter-relayer-proto.svg?style=svg)](https://circleci.com/gh/gballet/jupiter-relayer-proto)

# Jupiter relayer tool prototype

This tool has two functions:

  1. Simulate how transactions are applied by the jupiter contract;
  2. Serve as a toolkit for relayers to craft transactions

## Description

There are three commands:

 * `join` is the command used to craft a transaction that will let a user join the system;
 * `sendtx` is the command used to craft a transaction that will transfer funds from one jupiter account to another;
 * `apply` applies transactions generated by the previous two commands, against a local database

### Usage

Creating a `join` transaction:

```
$ cargo run join -a <sender addr> -v <amount to fund the jupiter address>
```

### Example run

```
$ cargo run join -a 0002 -v 1000
$ cargo run apply -d f85ccac0c483c22080c3c20280f84ef84cb840000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008400000002808203e88080 -s 0002
$ cargo run join -a 0001 -v 1000
$ cargo run apply -d f86bd9c0d392d1832000028ccb8400000002808203e88000c3c20204f84ef84cb840000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008400000001808203e88080 -s 0001
$ cargo run sendtx -f 0001 -t 0002 -v 100
$ cargo run apply -d f846f5c0e08fce208ccb84000000018082038480008fce208ccb8400000001808203848000d2c20280c28001c20280c20402c503c3808080cecd8400000001840000000280648080 -s 0001
```

### TODO

 - [ ] Nonce and signatures
 - [ ] Support for contracts
 - [ ] Support for merging several txs together `merge`
