//! The deliberate escape hatch for plaintext to a remote host.
//!
//! In its own test binary because it sets a process-global environment variable:
//! sharing a process with other tests would let it change their behaviour
//! depending on scheduling.
//!
//! It exists because one correctly-secured deployment is indistinguishable from
//! the broken one. Under a service mesh the process calls
//! `http://svc.ns.svc.cluster.local` and a sidecar transparently applies mTLS —
//! remote address, plaintext scheme, encrypted hop. Refusing that outright would
//! break deployments already doing the right thing.

use open_engine_core::http::{Credentials, PLAINTEXT_OPT_OUT};
use open_engine_core::policy::PolicyAuthority;

const REMOTE: &str = "http://policy.svc.cluster.local/decide";

#[test]
fn the_opt_out_permits_plaintext_to_a_remote_host() {
    // Refused by default.
    assert!(
        PolicyAuthority::from_uri(REMOTE, Credentials::none()).is_err(),
        "plaintext to a remote host must fail closed"
    );

    std::env::set_var(PLAINTEXT_OPT_OUT, "true");
    PolicyAuthority::from_uri(REMOTE, Credentials::none())
        .expect("the opt-out must permit a mesh-encrypted hop");

    // Only an affirmative value counts; anything else leaves the default intact.
    std::env::set_var(PLAINTEXT_OPT_OUT, "false");
    assert!(
        PolicyAuthority::from_uri(REMOTE, Credentials::none()).is_err(),
        "'false' must not read as opting out"
    );

    std::env::remove_var(PLAINTEXT_OPT_OUT);
}
