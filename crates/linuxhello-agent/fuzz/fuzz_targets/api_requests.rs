//! Property: the access rules of the state store hold for any sequence of calls through `Api`
//! (the module documentation of `state.rs`): only the PAM module of the user being authenticated
//! (root, or the user's own uid) can open a prompt; only the opener can change or close it; only the
//! opener, and for a prompt that root opened the subject user and the configured prompt hosts, can
//! read it or be told about changes; and no user can fill the store.
//!
//! The input is read as records of three bytes. The target keeps a model of the prompts it has
//! opened, updated only from the results it sees, and asserts after every call:
//!
//! 1. a caller with no uid is refused by every method;
//! 2. a successful `open_prompt` means the caller is root or the subject;
//! 3. a successful `report_state` or `close_prompt` means the caller opened that prompt;
//! 4. a successful `get_state` or `subscribe` means the caller is the opener, or the subject or a
//!    prompt host of a prompt root opened;
//! 5. no uid owns more prompts than the configured limit;
//! 6. no call panics.
#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use linuxhello_agent::api::{Api, ApiError, Caller};
use linuxhello_agent::state::Config;

/// The prompts opened so far: (opener uid, prompt id) to the subject uid.
type Model = HashMap<(u32, String), Option<u32>>;

/// The callers a record can choose: no uid, root, the prompt host, and three ordinary users.
const CALLERS: [Option<u32>; 6] = [None, Some(0), Some(990), Some(1000), Some(1001), Some(2000)];

/// Rule 4: whether `reader` may read prompt `id`, given what has been opened.
fn may_read(model: &Model, reader: u32, id: &str, hosts: &[u32]) -> bool {
    model.iter().any(|((opener, prompt), subject)| {
        prompt == id
            && (*opener == reader
                || (*opener == 0 && (*subject == Some(reader) || hosts.contains(&reader))))
    })
}

fuzz_target!(|data: &[u8]| {
    let config = Config::new(vec![990]);
    let (max, hosts) = (config.max_prompts_per_reporter, config.prompt_hosts.clone());
    let mut api = Api::new(config);
    let mut model = Model::new();

    for record in data.chunks_exact(3) {
        let (b0, b1, b2) = (record[0], record[1], record[2]);
        let who = CALLERS[usize::from(b0 % 6)];
        let caller = Caller { uid: who };
        let id = format!("{b2:064x}");
        let peer = format!(":1.{}", b2 % 20);
        let subject = match b2 % 3 {
            0 => None,
            1 => who,
            _ => Some(1000),
        };
        let method = b1 % 5;

        let Some(u) = who else {
            // Rule 1: nothing changes, so the model stays as it is.
            let denied = |what: &str, ok: bool, err: Option<ApiError>| {
                assert!(
                    !ok && err == Some(ApiError::Denied),
                    "rule 1: {what} without a uid"
                );
            };
            match method {
                0 => {
                    let r = api.open_prompt(caller, &id, subject);
                    denied("open_prompt", r.is_ok(), r.err());
                }
                1 => {
                    let r = api.report_state(caller, &id, "State", &["idle"]);
                    denied("report_state", r.is_ok(), r.err());
                }
                2 => {
                    let r = api.get_state(caller, &id);
                    denied("get_state", r.is_ok(), r.err());
                }
                3 => {
                    let r = api.subscribe(caller, &peer, &id);
                    denied("subscribe", r.is_ok(), r.err());
                }
                _ => {
                    let r = api.close_prompt(caller, &id);
                    denied("close_prompt", r.is_ok(), r.err());
                }
            }
            continue;
        };

        match method {
            0 => {
                if api.open_prompt(caller, &id, subject).is_ok() {
                    assert!(
                        u == 0 || subject == Some(u),
                        "rule 2: caller {caller:?} opened prompt {id} for {subject:?}"
                    );
                    model.insert((u, id.clone()), subject);
                }
            }
            1 => {
                if api.report_state(caller, &id, "State", &["idle"]).is_ok() {
                    assert!(
                        model.contains_key(&(u, id.clone())),
                        "rule 3: caller {caller:?}, report_state, prompt {id}"
                    );
                }
            }
            2 => {
                if api.get_state(caller, &id).is_ok() {
                    assert!(
                        may_read(&model, u, &id, &hosts),
                        "rule 4: caller {caller:?}, get_state, prompt {id}"
                    );
                }
            }
            3 => {
                if api.subscribe(caller, &peer, &id).is_ok() {
                    assert!(
                        may_read(&model, u, &id, &hosts),
                        "rule 4: caller {caller:?}, subscribe, prompt {id}"
                    );
                }
            }
            _ => {
                if api.close_prompt(caller, &id).is_ok() {
                    assert!(
                        model.remove(&(u, id.clone())).is_some(),
                        "rule 3: caller {caller:?}, close_prompt, prompt {id}"
                    );
                }
            }
        }

        // Rule 5: no uid owns more prompts than the limit.
        let mut owned: HashMap<u32, usize> = HashMap::new();
        for (opener, _) in model.keys() {
            *owned.entry(*opener).or_insert(0) += 1;
        }
        for (opener, count) in owned {
            assert!(
                count <= max,
                "rule 5: uid {opener} owns {count} prompts, the limit is {max}"
            );
        }
    }
});
