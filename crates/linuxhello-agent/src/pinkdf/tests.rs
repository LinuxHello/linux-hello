//! Tests of the PIN stretching: the function itself against a published vector, what makes two
//! results equal or different, and what is refused.

use super::*;

/// A salt of the bytes 0 to 15.
const SALT: [u8; SALT_BYTES] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Fast enough for a test: the smallest accepted parameters.
const FAST: Params = Params::MINIMUM;

/// The Argon2 crate computes Argon2id as the standard says: the test vector of RFC 9106, section
/// 5.3 (password, salt, secret and associated data of repeated bytes, 32 KiB, 3 passes, 4 lanes).
#[test]
fn the_crate_matches_rfc_9106() {
    let params = argon2::ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(argon2::AssociatedData::new(&[4; 12]).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let argon =
        Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0_u8; 32];
    argon
        .hash_password_into(&[1; 32], &[2; 16], &mut out)
        .unwrap();
    let expected: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53,
        0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01,
        0xe6, 0x59,
    ];
    assert_eq!(out, expected);
}

#[test]
fn the_same_pin_salt_and_parameters_give_the_same_result() {
    let a = stretch(b"1234", &SALT, &FAST).unwrap();
    let b = stretch(b"1234", &SALT, &FAST).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
}

#[test]
fn another_pin_salt_or_parameters_give_another_result() {
    let base = stretch(b"1234", &SALT, &FAST).unwrap();
    let other_pin = stretch(b"1235", &SALT, &FAST).unwrap();
    let mut salt = SALT;
    salt[15] ^= 1;
    let other_salt = stretch(b"1234", &salt, &FAST).unwrap();
    let more = Params {
        passes: FAST.passes + 1,
        ..FAST
    };
    let other_params = stretch(b"1234", &SALT, &more).unwrap();
    for other in [other_pin, other_salt, other_params] {
        assert_ne!(base.as_bytes(), other.as_bytes());
    }
}

/// A result that is pinned, so that a change of the normalisation, the algorithm or the way the
/// parameters are used cannot go unnoticed: every record in the field would stop opening.
#[test]
fn the_result_for_a_known_input_does_not_change() {
    let got = stretch(b"1234", &SALT, &FAST).unwrap();
    let hex: String = got.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, EXPECTED_1234, "the stretched PIN changed");
}

/// The result for "1234", [`SALT`] and [`FAST`].
const EXPECTED_1234: &str = "e3aa759ef5ce8fdf573cc14f72dae6c48dbd781f4d4ac6d7201f8a71e4855418";

#[test]
fn equivalent_texts_are_the_same_pin() {
    let ascii = stretch(b"1234", &SALT, &FAST).unwrap();
    // Full-width digits.
    let wide = stretch("１２３４".as_bytes(), &SALT, &FAST).unwrap();
    assert_eq!(ascii.as_bytes(), wide.as_bytes());
    // A letter composed, and the same letter as a base letter and a combining accent.
    let composed = stretch("pi\u{e9}ce1".as_bytes(), &SALT, &FAST).unwrap();
    let decomposed = stretch("pie\u{301}ce1".as_bytes(), &SALT, &FAST).unwrap();
    assert_eq!(composed.as_bytes(), decomposed.as_bytes());
}

#[test]
fn an_empty_pin_and_a_pin_that_is_not_text_are_refused() {
    assert_eq!(stretch(b"", &SALT, &FAST).err(), Some(KdfError::NotText));
    assert_eq!(
        stretch(&[0xff, 0xfe, 0x31], &SALT, &FAST).err(),
        Some(KdfError::NotText)
    );
}

#[test]
fn a_normal_form_that_does_not_fit_is_refused() {
    // U+FDFA becomes eighteen letters of two bytes each: 200 of them are far over the buffer.
    let long = "\u{fdfa}".repeat(200);
    assert_eq!(
        stretch(long.as_bytes(), &SALT, &FAST).err(),
        Some(KdfError::TooLong)
    );
    // And a shorter run of the same character fits.
    let fits = "\u{fdfa}".repeat(10);
    assert!(stretch(fits.as_bytes(), &SALT, &FAST).is_ok());
}

#[test]
fn parameters_outside_the_accepted_range_are_refused_before_any_work() {
    for params in [
        Params {
            memory_kib: Params::MINIMUM.memory_kib - 1,
            ..FAST
        },
        Params { passes: 1, ..FAST },
        Params { lanes: 0, ..FAST },
        Params {
            memory_kib: Params::MAXIMUM.memory_kib + 1,
            ..FAST
        },
        Params {
            passes: Params::MAXIMUM.passes + 1,
            ..FAST
        },
        Params {
            lanes: Params::MAXIMUM.lanes + 1,
            ..FAST
        },
    ] {
        assert!(!params.acceptable(), "{params:?}");
        assert_eq!(
            stretch(b"1234", &SALT, &params).err(),
            Some(KdfError::BadParams)
        );
    }
    assert!(
        Params::DEFAULT.acceptable()
            && Params::MINIMUM.acceptable()
            && Params::MAXIMUM.acceptable()
    );
}

/// Whether `T` implements `Debug`, decided at compile time: an inherent constant wins over the
/// trait's when it exists.
trait NotDebug {
    const IMPLEMENTS: bool = false;
}

impl<T> NotDebug for T {}

/// The probe: its inherent constant exists only for types that implement `Debug`.
struct Probe<T>(std::marker::PhantomData<T>);

impl<T: std::fmt::Debug> Probe<T> {
    const IMPLEMENTS: bool = true;
}

#[test]
fn the_stretched_pin_cannot_be_printed() {
    // The probe works: a type with Debug is seen, and the stretched PIN is not.
    const { assert!(Probe::<u8>::IMPLEMENTS) };
    const { assert!(!Probe::<Stretched>::IMPLEMENTS) };
}

/// Not a test of correctness: prints what the default parameters cost here, for the pull request.
/// Run it with `cargo test --release -p linuxhello-agent --lib pinkdf -- --ignored --nocapture`.
#[test]
#[ignore = "measures the cost; run by hand in release mode"]
fn the_cost_of_the_default_parameters() {
    let started = std::time::Instant::now();
    let runs = 5;
    for _ in 0..runs {
        stretch(b"123456", &SALT, &Params::DEFAULT).unwrap();
    }
    println!("default parameters: {:?} per PIN", started.elapsed() / runs);
}
