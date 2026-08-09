use nodavo_platform_macos::{KeychainError, MacKeychain, StoreDisposition};
use uuid::Uuid;

fn main() {
    if let Err(error) = run() {
        eprintln!("keychain_probe=failed error={error}");
        std::process::exit(1);
    }
    println!("keychain_probe=ok");
}

fn run() -> Result<(), KeychainError> {
    let store = MacKeychain::default();
    let account = format!("dev.nodavo.probe.{}", Uuid::new_v4().simple());
    let first = Uuid::new_v4().into_bytes();
    let second = Uuid::new_v4().into_bytes();

    match store.load(&account) {
        Err(KeychainError::NotFound) => {}
        Ok(_) => return Err(KeychainError::MalformedItem),
        Err(error) => return Err(error),
    }

    let result = (|| {
        if store.store(&account, &first)? != StoreDisposition::Created {
            return Err(KeychainError::MalformedItem);
        }
        if store.load(&account)?.expose_secret() != first {
            return Err(KeychainError::MalformedItem);
        }
        if store.store(&account, &second)? != StoreDisposition::Updated {
            return Err(KeychainError::MalformedItem);
        }
        if store.load(&account)?.expose_secret() != second {
            return Err(KeychainError::MalformedItem);
        }
        store.delete(&account)?;
        match store.load(&account) {
            Err(KeychainError::NotFound) => Ok(()),
            Ok(_) => Err(KeychainError::MalformedItem),
            Err(error) => Err(error),
        }
    })();

    if result.is_err() {
        let _ = store.delete(&account);
    }
    result
}
