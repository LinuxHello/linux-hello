//! Tests of the wire format: what encodes and decodes, and what is refused.

use super::*;

fn auth(b: u8) -> Auth {
    Zeroizing::new([b; AUTH_BYTES])
}

fn blobs() -> Blobs {
    Blobs {
        public: vec![1, 2, 3],
        private: vec![4; 300],
    }
}

/// A request as bytes and back.
fn roundtrip(request: &Request) -> Request {
    let body = encode_request(request).unwrap();
    decode_request(&body).unwrap()
}

#[test]
fn every_request_survives_encoding() {
    match roundtrip(&Request::Enrol { auth: auth(7) }) {
        Request::Enrol { auth: a } => assert_eq!(*a, [7; AUTH_BYTES]),
        _ => panic!("another request"),
    }
    match roundtrip(&Request::Verify {
        blobs: blobs(),
        auth: auth(8),
    }) {
        Request::Verify { blobs: b, auth: a } => {
            assert!(b == blobs());
            assert_eq!(*a, [8; AUTH_BYTES]);
        }
        _ => panic!("another request"),
    }
    match roundtrip(&Request::ChangeAuth {
        blobs: blobs(),
        old: auth(1),
        new: auth(2),
    }) {
        Request::ChangeAuth { blobs: b, old, new } => {
            assert!(b == blobs());
            assert_eq!((*old, *new), ([1; AUTH_BYTES], [2; AUTH_BYTES]));
        }
        _ => panic!("another request"),
    }
}

#[test]
fn a_request_that_is_not_exactly_one_request_is_refused() {
    let good = encode_request(&Request::Verify {
        blobs: blobs(),
        auth: auth(8),
    })
    .unwrap();
    // Cut short at every length, and with a byte too many.
    for length in 0..good.len() {
        assert!(decode_request(&good[..length]).is_none(), "cut at {length}");
    }
    let mut longer = good.to_vec();
    longer.push(0);
    assert!(decode_request(&longer).is_none());
    // An operation that does not exist, and an authorisation value of the wrong length.
    assert!(decode_request(&[0]).is_none());
    assert!(decode_request(&[9, 0, 0]).is_none());
    let mut short_auth = vec![1_u8, 0, 31];
    short_auth.extend_from_slice(&[0; 31]);
    assert!(decode_request(&short_auth).is_none());
}

#[test]
fn a_response_survives_encoding_and_a_bad_one_is_refused() {
    let with_blobs = Response {
        status: STATUS_OK,
        blobs: Some(blobs()),
    };
    let decoded = decode_response(&encode_response(&with_blobs).unwrap()).unwrap();
    assert_eq!(decoded.status, STATUS_OK);
    assert!(decoded.blobs.unwrap() == blobs());
    for status in [STATUS_OK, STATUS_WRONG, STATUS_LOCKED, STATUS_FAILED] {
        let plain = decode_response(&[status]).unwrap();
        assert_eq!(plain.status, status);
        assert!(plain.blobs.is_none());
    }
    assert!(decode_response(&[]).is_none());
    assert!(decode_response(&[4]).is_none(), "an unknown status");
    assert!(
        decode_response(&[0, 0, 5, 1]).is_none(),
        "a field that is cut short"
    );
}

#[test]
fn frames_have_a_length_and_a_limit() {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, b"hello").unwrap();
    assert_eq!(&bytes[..4], &5_u32.to_be_bytes());
    assert_eq!(
        read_frame(&mut bytes.as_slice())
            .unwrap()
            .unwrap()
            .as_slice(),
        b"hello"
    );
    // A length of zero or over the limit is refused without reading the body.
    assert!(read_frame(&mut 0_u32.to_be_bytes().as_slice())
        .unwrap()
        .is_none());
    let too_long = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
    assert!(read_frame(&mut too_long.as_slice()).unwrap().is_none());
    // A frame cut short is an error, not a short body.
    assert!(read_frame(&mut [0, 0, 0, 9, 1, 2].as_slice()).is_err());
    assert!(write_frame(&mut Vec::new(), &[]).is_err());
    assert!(write_frame(&mut Vec::new(), &vec![0; MAX_FRAME + 1]).is_err());
}
