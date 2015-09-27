use std::error;
use std::fmt;


#[derive(Debug)]
pub enum EntropyError {
    SourceFailed,
    Unknown(i32),
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            EntropyError::SourceFailed => write!(f, "SourceFailed"),
            EntropyError::Unknown(err) => write!(f, "Unknown failure: {}", err),
        }
    }
}

impl error::Error for EntropyError {
    fn description(&self) -> &str {
        match *self {
            EntropyError::SourceFailed => "The entropy source failed",
            EntropyError::Unknown(_) => "An unknown error happened",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}
