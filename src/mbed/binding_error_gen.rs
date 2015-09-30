#![macro_use]

macro_rules! create_error {
    ($ErrorName:ident: $($en:ident => $ev:expr),+ ) => {
        #[derive(Debug)]
        pub enum $ErrorName {
            $( $en, )+
            Unknown(i32),
        }

        impl $ErrorName {
            pub fn from_code(err_code : i32) -> $ErrorName {
                $(
                    if err_code == $ev.0 {
                        $ErrorName::$en
                    }
                )else+
                else {
                    $ErrorName::Unknown(err_code)
                }
            }

            pub fn to_int(&self) -> i32 {
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

        impl From<i32> for $ErrorName {
            fn from(err_code: i32) -> Self {
                $ErrorName::from_code(err_code)
            }
        }
    }
}
