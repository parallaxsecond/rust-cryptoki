//! # Thread-Local Session Pattern Example
//!
//! This example demonstrates how to safely use cryptoki in a multi-threaded
//! application by combining:
//!
//! 1. **Shared Pkcs11 context** - One context for all threads (via Arc)
//! 2. **Thread-local Sessions** - Each thread has its own Session (via thread_local!)
//!
//! ## Why This Pattern?
//!
//! - **Pkcs11 context**: Is Send + Sync, can be shared via Arc (cheap clone)
//! - **Session**: Is Send but NOT Sync (can transfer ownership, cannot share)
//!
//! The Session type deliberately prevents sharing across threads by not
//! implementing Sync. This matches PKCS#11 C specification where sessions
//! are not thread-safe.
//!
//! ## Architecture
//!
//! ```text
//! +---------------------------------------+
//! | static PKCS11_CTX: Arc<Pkcs11>        | <- Shared across threads
//! +---------------------------------------+
//!          |
//!          +---> Thread 1: thread_local! { Session<'_> }
//!          +---> Thread 2: thread_local! { Session<'_> }
//!          +---> Thread 3: thread_local! { Session<'_> }
//! ```
//!
//! ## Running This Example
//!
//! ```bash
//! export TEST_PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm2.so
//! cargo run --example thread_local_session
//! ```

use std::cell::RefCell;
use std::env;
use std::sync::OnceLock;
use std::thread;

use testresult::TestResult;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

const USER_PIN: &str = "fedcba";
const SO_PIN: &str = "abcdef";

// Global PKCS11 context shared across all threads using Arc for cheap cloning
static PKCS11_CTX: OnceLock<Pkcs11> = OnceLock::new();

// Session is Send but NOT Sync: it can be moved between threads
// but cannot be shared. Each thread must have its own Session instance.
thread_local! {
    static PKCS11_SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

/// Initialize the global PKCS11 context once.
/// This sets up the token and user PIN for all threads to use.
fn init_pkcs11_context() -> TestResult {
    // Load library from env or default path
    let lib_path = env::var("TEST_PKCS11_MODULE")
        .unwrap_or_else(|_| "/usr/local/lib/softhsm/libsofthsm2.so".to_string());
    let pkcs11 = Pkcs11::new(lib_path)?;

    // CRITICAL: Use OsThreads for multi-threaded applications.
    // This tells the PKCS#11 library to use OS-level locking.
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    // Get first slot with token
    let slot = pkcs11.get_slots_with_token()?[0];

    // Initialize token
    let so_pin = AuthPin::new(SO_PIN.into());
    pkcs11.init_token(slot, &so_pin, "Test Token")?;

    // Initialize user PIN
    let user_pin = AuthPin::new(USER_PIN.into());
    {
        let session = pkcs11.open_rw_session(slot)?;
        session.login(UserType::So, Some(&so_pin))?;
        session.init_pin(&user_pin)?;
    } // Session auto-closes here via Drop

    // Store context in global OnceLock wrapped in Arc
    PKCS11_CTX
        .set(pkcs11)
        .expect("PKCS11 context already initialized");

    println!("PKCS11 context initialized successfully");
    Ok(())
}

/// Execute a closure with a valid thread-local session.
///
/// This function:
/// 1. Checks if the thread has a valid session
/// 2. Opens a new session if needed (or if existing is invalid)
/// 3. Executes the closure with the session reference
///
/// The session persists for the lifetime of the thread and auto-closes
/// when the thread exits via Drop.
fn with_session<F, R>(f: F) -> TestResult<R>
where
    F: FnOnce(&Session) -> TestResult<R>,
{
    PKCS11_SESSION.with(|session_cell| {
        let mut session_opt = session_cell.borrow_mut();

        // Validate existing session by checking get_session_info().
        // If this returns an error, the session handle is no longer valid.
        let needs_reopen = session_opt
            .as_ref()
            .map(|s| {
                let session_info = s.get_session_info();
                println!(
                    "Thread {:?}: Session info check: {:?}",
                    thread::current().id(),
                    session_info
                );
                session_info.is_err()
            })
            .unwrap_or(true);

        if needs_reopen {
            // Explicitly set to None to trigger Drop on the old session.
            // This ensures C_CloseSession is called before opening a new session.
            *session_opt = None;

            // Get global context (cheap Arc clone)
            let ctx = PKCS11_CTX
                .get()
                .expect("PKCS11 context should be initialized");

            // Get slot with token
            let slot = ctx.get_slots_with_token()?[0];

            // Open new session (R/W for key generation)
            let new_session = ctx.open_rw_session(slot)?;

            // Login as normal user
            let user_pin = AuthPin::new(USER_PIN.into());
           new_session.login(UserType::User, Some(&user_pin))?;

            println!("Thread {:?}: Opened new RW session", thread::current().id());

            // Store in thread-local storage
            *session_opt = Some(new_session);
        } else {
            println!(
                "Thread {:?}: Reusing existing session",
                thread::current().id()
            );
        }

        // Execute closure with session reference
        let session_ref = session_opt.as_ref().expect("Session should exist");
        f(session_ref)
    })
}

/// Generate an RSA key pair and sign data using thread-local session.
/// Demonstrates that each thread has its own session and can perform
/// cryptographic operations independently.
///
/// This function makes multiple calls to with_session() to demonstrate
/// session reuse within the same thread.
fn generate_and_sign(thread_id: usize) -> TestResult {
    println!(
        "Thread {:?} (worker {}): Starting operations",
        thread::current().id(),
        thread_id
    );

    // First call: generate keys
    let (_public, private) = with_session(|session| {
        println!(
            "Thread {:?} (worker {}): Generating RSA key pair",
            thread::current().id(),
            thread_id
        );

        // Public key template
        let pub_key_template = vec![
            Attribute::Token(false), // Session object (auto-cleanup)
            Attribute::Private(false),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::ModulusBits(1024.into()),
        ];

        // Private key template
        let priv_key_template = vec![
            Attribute::Token(false), // Session object
            Attribute::Sign(true),   // Allow signing
        ];

        // Generate key pair
        let keys = session.generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &pub_key_template,
            &priv_key_template,
        )?;

        println!(
            "Thread {:?} (worker {}): Keys generated (pub: {}, priv: {})",
            thread::current().id(),
            thread_id,
            keys.0.handle(),
            keys.1.handle()
        );

        Ok(keys)
    })?;

    // Second call: first signature (reuses the session)
    with_session(|session| {
        let data = format!("Message 1 from thread {}", thread_id);
        let signature = session.sign(&Mechanism::RsaPkcs, private, data.as_bytes())?;
        println!(
            "Thread {:?} (worker {}): First signature: {} bytes",
            thread::current().id(),
            thread_id,
            signature.len()
        );
        Ok(())
    })?;

    // Third call: second signature (reuses the session again)
    with_session(|session| {
        let data = format!("Message 2 from thread {}", thread_id);
        let signature = session.sign(&Mechanism::RsaPkcs, private, data.as_bytes())?;
        println!(
            "Thread {:?} (worker {}): Second signature: {} bytes",
            thread::current().id(),
            thread_id,
            signature.len()
        );
        Ok(())
    })?;

    println!(
        "Thread {:?} (worker {}): All operations completed",
        thread::current().id(),
        thread_id
    );

    Ok(())
}

fn main() -> TestResult {
    println!("Thread-Local Session Pattern Example");
    println!("====================================\n");
    println!("This example demonstrates:");
    println!("- Sharing Pkcs11 context across threads (via Arc)");
    println!("- Per-thread Sessions (via thread_local!)");
    println!("- Automatic session lifecycle management");
    println!("- Session reuse within the same thread\n");

    // Initialize global context once
    println!("Initializing PKCS11 context...");
    init_pkcs11_context()?;
    println!();

    // Spawn multiple threads
    println!("Spawning 3 worker threads...\n");
    let mut handles = vec![];

    for i in 0..3 {
        let handle = thread::spawn(move || generate_and_sign(i));
        handles.push(handle);
    }

    // Wait for all threads and check results
    println!();
    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .join()
            .unwrap_or_else(|_| panic!("Thread {} panicked", i))?;
    }

    println!("\nAll threads completed successfully!");
    println!("Note: Each thread had its own Session instance, reused across multiple operations.");

    Ok(())
}
