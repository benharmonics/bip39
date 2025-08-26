use clap::{arg, ArgMatches, Command};
use sha2::{Digest, Sha256, Sha512};

const WORDS: &str = include_str!("../words.txt");

fn checksum_bits(ms_length: usize) -> usize {
  // CS in bits
  ms_length / 3
}

fn entropy_bits(ms_length: usize) -> usize {
  // ENT in bits
  32 * ms_length / 3
}

fn entropy_bytes(ms_length: usize) -> usize {
  // ENT in bytes (always byte-aligned)
  entropy_bits(ms_length) / 8
}

fn bytes_to_hex(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut s = String::with_capacity(bytes.len() * 2);
  for &b in bytes {
    s.push(HEX[(b >> 4) as usize] as char);
    s.push(HEX[(b & 0x0f) as usize] as char);
  }
  s
}

/// Split a big-endian bitstream into 11-bit indices (0..=2047), MSB-first,
/// consuming exactly `total_bits` from `bytes`.
fn bitstream_to_11_bit_indices(stream: &[u8], total_bits: usize) -> Vec<usize> {
  debug_assert!(total_bits % 11 == 0);
  debug_assert!(total_bits <= stream.len() * 8);

  let n = total_bits / 11;
  let mut out = Vec::with_capacity(n);
  let mut buf: u32 = 0;
  let mut buf_bits: usize = 0;
  let mut remaining_bits = total_bits;

  for &b in stream {
    if remaining_bits == 0 {
      break;
    }
    let take = remaining_bits.min(8);
    let top = (b >> (8 - take)) as u32;
    buf = (buf << take) | top;
    buf_bits += take;
    remaining_bits -= take;

    while buf_bits >= 11 {
      let shift = buf_bits - 11;
      let idx = ((buf >> shift) & 0x7FF) as usize;
      out.push(idx);
      buf &= if shift == 0 { 0 } else { (1u32 << shift) - 1 };
      buf_bits -= 11;
    }
  }
  debug_assert_eq!(remaining_bits, 0);
  debug_assert_eq!(buf_bits, 0);

  out
}

fn derive_seed(passphrase: &str, mnemonic: &str) -> String {
  let salt = String::from("mnemonic") + passphrase;
  let mut res = [0u8; 64];
  pbkdf2::pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut res);
  bytes_to_hex(&res)
}

fn random_mnemonic_sentence(ms_length: usize, entropy: Option<Vec<u8>>) -> String {
  let entropy_len = entropy_bytes(ms_length);
  let entropy = entropy.unwrap_or_else(|| {
    let mut v = vec![0u8; entropy_len];
    getrandom::fill(&mut v).expect("failed to generate entropy");
    v
  });
  debug_assert!((12..=24).contains(&ms_length) && ms_length % 3 == 0);
  debug_assert_eq!(entropy.len(), entropy_len);

  let mut stream = Vec::with_capacity(entropy_len + 1); // Entropy + single checksum byte
  let hash = Sha256::digest(&entropy);
  stream.extend_from_slice(&entropy);
  stream.push(*hash.first().expect("sha256 returns at least one byte"));

  let total_bits = entropy_bits(ms_length) + checksum_bits(ms_length);
  let word_idxs = bitstream_to_11_bit_indices(&stream, total_bits);

  let word_list: Vec<_> = WORDS.split('\n').collect();
  word_idxs
    .into_iter()
    .map(|idx| *word_list.get(idx).expect("word list long enough"))
    .collect::<Vec<_>>()
    .join(" ")
}

fn run_cmd_seed(matches: &ArgMatches) {
  let passphrase: &String = matches
    .get_one("passphrase")
    .expect("valid empty default passphrase");
  let mnemonic: &String = matches
    .get_one("mnemonic")
    .expect("mnemonic should be a required argument");
  println!("{}", derive_seed(passphrase, mnemonic));
}

fn run_cmd_new(matches: &ArgMatches) {
  let num_words: usize = *matches
    .get_one("wordcount")
    .expect("word count should have default value");
  println!("{}", random_mnemonic_sentence(num_words, None));
}

pub fn run() {
  let matches = Command::new(env!("CARGO_CRATE_NAME"))
    .version("v0.1")
    .author("benharmonics")
    .about("Derive random BIP-39 mnemonics or convert mnemonics to private keys")
    .arg_required_else_help(true)
    .subcommand(
      Command::new("new")
        .about("Create new random BIP-39 mnemonic")
        .version("v0.1")
        .arg(
          arg!([WORD_COUNT] "Number of words in the mnemonic - must be 12, 15, 18, 21, or 24")
            .id("wordcount")
            .value_parser(clap::builder::ValueParser::new(|s: &str| {
              match s.parse::<usize>() {
                Ok(ms_length) => {
                  if !(12..=24).contains(&ms_length) || ms_length % 3 != 0 {
                    Err("expected 12, 15, 18, 21, or 24")
                  } else {
                    Ok(ms_length)
                  }
                }
                Err(_) => Err("expected integer (one of 12, 15, 18, 21, or 24)"),
              }
            }))
            .default_value("12"),
        ),
    )
    .subcommand(
      Command::new("seed")
        .about("Generate a 32-byte seed value from a mnemonic")
        .version("v0.1")
        .arg(
          arg!(<MNEMONIC> "Valid BIP-39 mnemonic - must be 12, 15, 18, 21, or 24 words")
            .id("mnemonic")
            .required(true),
        )
        .arg(
          arg!(-p --passphrase [PHRASE] "Optional passphrase for additional security")
            .default_value(""),
        ),
    )
    .get_matches();

  match matches.subcommand() {
    None => unreachable!("should be validated by .arg_required_else_help"),
    Some((subcmd_name, subcmd_matches)) => match subcmd_name {
      "new" => run_cmd_new(subcmd_matches),
      "seed" => run_cmd_seed(subcmd_matches),
      _ => unreachable!("unknown command"),
    },
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const DERIV_KEY: &str = "TREZOR";

  #[test]
  fn entropy_to_mnemonic_12_1() {
    let ms_length = 12;
    let entropy = vec![0x00u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
  }

  #[test]
  fn entropy_to_mnemonic_12_2() {
    let ms_length = 12;
    let entropy = vec![0x7fu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "legal winner thank year wave sausage worth useful legal winner thank yellow"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_3() {
    let ms_length = 12;
    let entropy = vec![0x80u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_4() {
    let ms_length = 12;
    let entropy = vec![0xffu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
  }

  #[test]
  fn entropy_to_mnemonic_12_5() {
    let ms_length = 12;
    let entropy = vec![
      0x9e, 0x88, 0x5d, 0x95, 0x2a, 0xd3, 0x62, 0xca, 0xeb, 0x4e, 0xfe, 0x34, 0xa8, 0xe9, 0x1b,
      0xd2,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_6() {
    let ms_length = 12;
    let entropy = vec![
      0xc0, 0xba, 0x5a, 0x8e, 0x91, 0x41, 0x11, 0x21, 0x0f, 0x2b, 0xd1, 0x31, 0xf3, 0xd5, 0xe0,
      0x8d,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "scheme spot photo card baby mountain device kick cradle pact join borrow"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_7() {
    let ms_length = 12;
    let entropy = vec![
      0x23, 0xdb, 0x81, 0x60, 0xa3, 0x1d, 0x3e, 0x0d, 0xca, 0x36, 0x88, 0xed, 0x94, 0x1a, 0xdb,
      0xf3,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "cat swing flag economy stadium alone churn speed unique patch report train"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_8() {
    let ms_length = 12;
    let entropy = vec![
      0xf3, 0x0f, 0x8c, 0x1d, 0xa6, 0x65, 0x47, 0x8f, 0x49, 0xb0, 0x01, 0xd9, 0x4c, 0x5f, 0xc4,
      0x52,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "vessel ladder alter error federal sibling chat ability sun glass valve picture"
    );
  }

  #[test]
  fn entropy_to_mnemonic_18_1() {
    let ms_length = 18;
    let entropy = vec![0x00u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent");
  }

  #[test]
  fn entropy_to_mnemonic_18_2() {
    let ms_length = 18;
    let entropy = vec![0x7fu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will");
  }

  #[test]
  fn entropy_to_mnemonic_18_3() {
    let ms_length = 18;
    let entropy = vec![0x80u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always");
  }

  #[test]
  fn entropy_to_mnemonic_18_4() {
    let ms_length = 18;
    let entropy = vec![0xffu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"
    );
  }

  #[test]
  fn entropy_to_mnemonic_18_5() {
    let ms_length = 18;
    let entropy = vec![
      0x66, 0x10, 0xb2, 0x59, 0x67, 0xcd, 0xcc, 0xa9, 0xd5, 0x98, 0x75, 0xf5, 0xcb, 0x50, 0xb0,
      0xea, 0x75, 0x43, 0x33, 0x11, 0x86, 0x9e, 0x93, 0x0b,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"
    );
  }

  #[test]
  fn entropy_to_mnemonic_18_6() {
    let ms_length = 18;
    let entropy = vec![
      0x6d, 0x9b, 0xe1, 0xee, 0x6e, 0xbd, 0x27, 0xa2, 0x58, 0x11, 0x5a, 0xad, 0x99, 0xb7, 0x31,
      0x7b, 0x9c, 0x8d, 0x28, 0xb6, 0xd7, 0x64, 0x31, 0xc3,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave");
  }

  #[test]
  fn entropy_to_mnemonic_18_7() {
    let ms_length = 18;
    let entropy = vec![
      0x81, 0x97, 0xa4, 0xa4, 0x7f, 0x04, 0x25, 0xfa, 0xea, 0xa6, 0x9d, 0xee, 0xbc, 0x05, 0xca,
      0x29, 0xc0, 0xa5, 0xb5, 0xcc, 0x76, 0xce, 0xac, 0xc0,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access");
  }

  #[test]
  fn entropy_to_mnemonic_18_8() {
    let ms_length = 18;
    let entropy = vec![
      0xc1, 0x0e, 0xc2, 0x0d, 0xc3, 0xcd, 0x9f, 0x65, 0x2c, 0x7f, 0xac, 0x2f, 0x12, 0x30, 0xf7,
      0xa3, 0xc8, 0x28, 0x38, 0x9a, 0x14, 0x39, 0x2f, 0x05,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump");
  }

  #[test]
  fn entropy_to_mnemonic_24_1() {
    let ms_length = 24;
    let entropy = vec![0x00u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");
  }

  #[test]
  fn entropy_to_mnemonic_24_2() {
    let ms_length = 24;
    let entropy = vec![0x7fu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title");
  }

  #[test]
  fn entropy_to_mnemonic_24_3() {
    let ms_length = 24;
    let entropy = vec![0x80u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless");
  }

  #[test]
  fn entropy_to_mnemonic_24_4() {
    let ms_length = 24;
    let entropy = vec![0xffu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote");
  }

  #[test]
  fn entropy_to_mnemonic_24_5() {
    let ms_length = 24;
    let entropy = vec![
      0x68, 0xa7, 0x9e, 0xac, 0xa2, 0x32, 0x48, 0x73, 0xea, 0xcc, 0x50, 0xcb, 0x9c, 0x6e, 0xca,
      0x8c, 0xc6, 0x8e, 0xa5, 0xd9, 0x36, 0xf9, 0x87, 0x87, 0xc6, 0x0c, 0x7e, 0xbc, 0x74, 0xe6,
      0xce, 0x7c,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length");
  }

  #[test]
  fn entropy_to_mnemonic_24_6() {
    let ms_length = 24;
    let entropy = vec![
      0x9f, 0x6a, 0x28, 0x78, 0xb2, 0x52, 0x07, 0x99, 0xa4, 0x4e, 0xf1, 0x8b, 0xc7, 0xdf, 0x39,
      0x4e, 0x70, 0x61, 0xa2, 0x24, 0xd2, 0xc3, 0x3c, 0xd0, 0x15, 0xb1, 0x57, 0xd7, 0x46, 0x86,
      0x98, 0x63,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside");
  }

  #[test]
  fn entropy_to_mnemonic_24_7() {
    let ms_length = 24;
    let entropy = vec![
      0x06, 0x6d, 0xca, 0x1a, 0x2b, 0xb7, 0xe8, 0xa1, 0xdb, 0x28, 0x32, 0x14, 0x8c, 0xe9, 0x93,
      0x3e, 0xea, 0x0f, 0x3a, 0xc9, 0x54, 0x8d, 0x79, 0x31, 0x12, 0xd9, 0xa9, 0x5c, 0x94, 0x07,
      0xef, 0xad,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform");
  }

  #[test]
  fn entropy_to_mnemonic_24_8() {
    let ms_length = 24;
    let entropy = vec![
      0xf5, 0x85, 0xc1, 0x1a, 0xec, 0x52, 0x0d, 0xb5, 0x7d, 0xd3, 0x53, 0xc6, 0x95, 0x54, 0xb2,
      0x1a, 0x89, 0xb2, 0x0f, 0xb0, 0x65, 0x09, 0x66, 0xfa, 0x0a, 0x9d, 0x6f, 0x74, 0xfd, 0x98,
      0x9d, 0x8f,
    ];
    let ms = random_mnemonic_sentence(ms_length, Some(entropy));
    assert_eq!(ms, "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold");
  }

  #[test]
  fn mnemonic_to_seed_12_1() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
  }

  #[test]
  fn mnemonic_to_seed_12_2() {
    let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607");
  }

  #[test]
  fn mnemonic_to_seed_12_3() {
    let mnemonic =
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8");
  }

  #[test]
  fn mnemonic_to_seed_12_4() {
    let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069");
  }

  #[test]
  fn mnemonic_to_seed_12_5() {
    let mnemonic = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028");
  }

  #[test]
  fn mnemonic_to_seed_18_1() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa");
  }

  #[test]
  fn mnemonic_to_seed_18_2() {
    let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd");
  }

  #[test]
  fn mnemonic_to_seed_18_3() {
    let mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65");
  }

  #[test]
  fn mnemonic_to_seed_18_4() {
    let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528");
  }

  #[test]
  fn mnemonic_to_seed_18_5() {
    let mnemonic = "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac");
  }

  #[test]
  fn mnemonic_to_seed_24_1() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8");
  }

  #[test]
  fn mnemonic_to_seed_24_2() {
    let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87");
  }

  #[test]
  fn mnemonic_to_seed_24_3() {
    let mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f");
  }

  #[test]
  fn mnemonic_to_seed_24_4() {
    let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    let seed = derive_seed(DERIV_KEY, mnemonic);
    assert_eq!(seed, "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad");
  }
}
