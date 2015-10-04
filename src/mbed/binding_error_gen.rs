#![macro_use]

macro_rules! create_error {
    ($ErrorName:ident: $($en:ident => $ev:expr),+ ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $ErrorName {
            $( $en, )+
            Unknown(i32),
        }

        impl $ErrorName {
            pub fn from_code(r : i32) -> Result<i32, Self> {
                if r >= 0 {
                    Ok(r)
                }
                $(
                    else if r == $ev.0 {
                        Err($ErrorName::$en)
                    }
                )+
                else {
                    Err($ErrorName::Unknown(r))
                }
            }

        }

        impl CError for $ErrorName {
            fn to_int(&self) -> i32 {
                match *self {
                    // Both underlying errors already impl `Display`, so we defer to
                    // their implementations.
                    $( $ErrorName::$en => $ev.0, )+
                    $ErrorName::Unknown(err) => err,
                }
            }
        }

        impl fmt::Display for $ErrorName {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match *self {
                    // Both underlying errors already impl `Display`, so we defer to
                    // their implementations.
                    $( $ErrorName::$en => f.write_str($ev.1), )+
                    $ErrorName::Unknown(err) => write!(f, "Unknown failure: 0x{:X}", -err),
                }
            }
        }

        impl error::Error for $ErrorName {
            fn description(&self) -> &str {
                match *self {
                    $( $ErrorName::$en => $ev.1, )+
                    $ErrorName::Unknown(_) => "An unknown error happened",
                }
            }

            fn cause(&self) -> Option<&error::Error> {
                None
            }
        }

    }
}
