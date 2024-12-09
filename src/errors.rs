
#[cfg(feature = "runtime-async-std")]
pub use async_std::future::TimeoutError;

#[cfg(feature = "runtime-tokio")]
pub use tokio::time::error::Elapsed as TimeoutError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Dns(#[from] dns_parser::Error),
    #[error(transparent)]
    TimeoutError(#[from] TimeoutError),
}
