# bip39

Generate BIP-39 mnemonic phrases and parse existing mnemonics into seeds

[Reference](https://bips.dev/39/)

## Overview

BIP-39 describes the implementation of a mnemonic phrase - a group of easy-to-remember words - for the generation of deterministic wallets.

There are two parts to BIP-39: generating the mnemonic and converting it to a binary seed. The seed can then be used to generate deterministic wallets using BIP-32.

This project is a small implementation of BIP-39 which can generate English mnemonic phrases consisting of 12, 15, 18, 21, or 24 words.

## Installation

You will need to have the `cargo` toolchain installed to build this tool. Installation should be relatively easy, though:

```bash
cargo install /path/to/bip39
```

## Usage

There are two basic commands to use: `new` and `seed`. The `new` command will generate a random mnemonic phrase with a given number of words (with a default of 12). The `seed` command takes in an existing mnemonic phrase and generates a 64-byte binary seed, given as a hexadecimal string (128 hexadecimal characters).

**EXAMPLE 1)** Generate a 12-word mnemonic phrase

```bash
bip39 new
```

**EXAMPLE 2)** Generate a 21-word mnemonic phrase (the specification supports 12, 15, 18, 21, or 24 words in a phrase)

```bash
bip39 new 21
```

**EXAMPLE 3)** Convert a mnemonic phrase to a binary seed

```bash
bip39 seed 'gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog'
```

*Note*: In fact, there are no checks that your mnemonic is valid when converting to a binary seed. You could generate the binary seed of any text, but I wouldn't recommend using just any old text as a secure mnemonic. It's also possible to "manually" generate a mnemonic by just picking a few of your favorite words; I wouldn't recommend this either. You're not as unpredictable as you might think you are - it's best to just have a computer generate a mnemonic instead.
