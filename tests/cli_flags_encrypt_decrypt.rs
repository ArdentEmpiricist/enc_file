use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::{fs, io::Read, process::Command};

fn read_all(path: &std::path::Path) -> Vec<u8> {
    let mut f = fs::File::open(path).expect("open");
    let mut v = Vec::new();
    f.read_to_end(&mut v).expect("read");
    v
}

fn make_pw(td: &assert_fs::TempDir) -> std::path::PathBuf {
    let pw = td.child("pw.txt");
    pw.write_str("pw").expect("write pw");
    pw.path().to_path_buf()
}

fn make_plain_small(td: &assert_fs::TempDir) -> std::path::PathBuf {
    let p = td.child("a.txt");
    p.write_str("hello\nworld\n").expect("write");
    p.path().to_path_buf()
}

fn make_plain_big(td: &assert_fs::TempDir) -> std::path::PathBuf {
    // ~1.3 MiB to ensure multiple streaming chunks
    let p = td.child("big.bin");
    let mut data = Vec::with_capacity(1_300_000);
    for i in 0..1_300_000 {
        data.push((i % 251) as u8);
    }
    p.write_binary(&data).expect("write");
    p.path().to_path_buf()
}

// ------------------------- Non-stream roundtrips -----------------------------

#[test]
fn cli_nonstream_xchacha_long_password_file() -> Result<(), Box<dyn std::error::Error>> {
    // enc + dec both use LONG --password-file
    let td = assert_fs::TempDir::new()?;
    let plain = make_plain_small(&td);
    let ct = td.child("a_x.enc");
    let out = td.child("a_x.out");
    let pw = make_pw(&td);

    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["--password-file"])
        .arg(&pw)
        .assert()
        .success();

    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--out"])
        .arg(out.path())
        .args(["--password-file"])
        .arg(&pw)
        .assert()
        .success();

    assert_eq!(read_all(out.path()), read_all(&plain));
    td.close()?;
    Ok(())
}

#[test]
fn cli_nonstream_aes_short_p_on_enc_and_dec() -> Result<(), Box<dyn std::error::Error>> {
    // enc + dec both use SHORT -p
    let td = assert_fs::TempDir::new()?;
    let plain = make_plain_small(&td);
    let ct = td.child("a_aes.enc");
    let out = td.child("a_aes.out");
    let pw = make_pw(&td);

    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["-p"]) // <-- short on enc
        .arg(&pw)
        .args(["--alg", "aes"])
        .assert()
        .success();

    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--out"])
        .arg(out.path())
        .args(["-p"]) // <-- short on dec
        .arg(&pw)
        .assert()
        .success();

    assert_eq!(read_all(out.path()), read_all(&plain));
    td.close()?;
    Ok(())
}

// ------------------------- Streaming roundtrips ------------------------------

#[test]
fn cli_streaming_xchacha_enc_short_p_dec_long() -> Result<(), Box<dyn std::error::Error>> {
    // enc uses -p (short), dec uses --password-file (long)
    let td = assert_fs::TempDir::new()?;
    let plain = make_plain_big(&td);
    let ct = td.child("big_x.enc");
    let out = td.child("big_x.out");
    let pw = make_pw(&td);

    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["-p"]) // <-- short on enc
        .arg(&pw)
        .args(["--stream"])
        .args(["--chunk-size", "65536"])
        .assert()
        .success();

    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--out"])
        .arg(out.path())
        .args(["--password-file"]) // <-- long on dec
        .arg(&pw)
        .assert()
        .success();

    assert_eq!(read_all(out.path()), read_all(&plain));
    td.close()?;
    Ok(())
}

#[test]
fn cli_streaming_aes_enc_long_dec_short_p() -> Result<(), Box<dyn std::error::Error>> {
    // enc uses --password-file (long), dec uses -p (short)
    let td = assert_fs::TempDir::new()?;
    let plain = make_plain_big(&td);
    let ct = td.child("big_aes.enc");
    let out = td.child("big_aes.out");
    let pw = make_pw(&td);

    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["--password-file"]) // <-- long on enc
        .arg(&pw)
        .args(["--stream"])
        .args(["--chunk-size", "65536"])
        .args(["--alg", "aes"])
        .assert()
        .success();

    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--out"])
        .arg(out.path())
        .args(["-p"]) // <-- short on dec
        .arg(&pw)
        .assert()
        .success();

    assert_eq!(read_all(out.path()), read_all(&plain));
    td.close()?;
    Ok(())
}

// ------------------------- Armor (non-stream) --------------------------------

#[test]
fn cli_nonstream_armor_xchacha_enc_short_p_dec_long() -> Result<(), Box<dyn std::error::Error>> {
    // enc uses -p (short), dec uses --password-file (long)
    let td = assert_fs::TempDir::new()?;
    let plain = make_plain_small(&td);
    let ct = td.child("a_armored.enc"); // ASCII-armored contents
    let out = td.child("a_armored.out");
    let pw = make_pw(&td);

    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["-p"]) // <-- short on enc
        .arg(&pw)
        .args(["--armor"])
        .assert()
        .success();

    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--out"])
        .arg(out.path())
        .args(["--password-file"]) // <-- long on dec
        .arg(&pw)
        .assert()
        .success();

    assert_eq!(read_all(out.path()), read_all(&plain));
    td.close()?;
    Ok(())
}

// ------------------------- Overwrite behavior --------------------------------

#[test]
fn cli_enc_overwrite_requires_force_long_and_works_with_long_p()
-> Result<(), Box<dyn std::error::Error>> {
    // enc has --force (long); password-file can be -p or --password-file; we use -p here
    let td = assert_fs::TempDir::new()?;
    let plain = make_plain_small(&td);
    let ct = td.child("dup.enc");
    let pw = make_pw(&td);

    // first enc
    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["-p"]) // <-- short on enc
        .arg(&pw)
        .assert()
        .success();

    // without --force must fail
    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["-p"])
        .arg(&pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("use --force"));

    // with --force must succeed
    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["-p"])
        .arg(&pw)
        .args(["--force"])
        .assert()
        .success();

    td.close()?;
    Ok(())
}

#[test]
fn cli_dec_overwrite_requires_force_short_and_long() -> Result<(), Box<dyn std::error::Error>> {
    // dec overwrite tested with both -f (short) and --force (long)
    let td = assert_fs::TempDir::new()?;
    let plain = make_plain_small(&td);
    let pw = make_pw(&td);

    // create ciphertext
    let ct = td.child("dec_overwrite.enc");
    Command::cargo_bin("enc-file")?
        .args(["enc", "--in"])
        .arg(&plain)
        .args(["--out"])
        .arg(ct.path())
        .args(["-p"]) // try short -p on enc as well
        .arg(&pw)
        .assert()
        .success();

    // default dec target (strip ".enc")
    let dest = td.child("dec_overwrite");
    dest.write_str("PREEXISTING").expect("write");

    // dec without force -> must fail
    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["-p"]) // short -p on dec
        .arg(&pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("use --force"));
    dest.assert("PREEXISTING");

    // dec with short -f
    Command::cargo_bin("enc-file")?
        .args(["dec", "-i"])
        .arg(ct.path())
        .args(["-p"])
        .arg(&pw)
        .args(["-f"])
        .assert()
        .success();

    // recreate and test long --force too
    dest.write_str("PREEXISTING2").expect("write");
    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["-p"])
        .arg(&pw)
        .args(["--force"])
        .assert()
        .success();

    assert_eq!(read_all(dest.path()), read_all(&plain));
    td.close()?;
    Ok(())
}
