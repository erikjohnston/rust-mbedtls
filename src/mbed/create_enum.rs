#![macro_use]

macro_rules! create_enum {
    ($Name:ident: $( $n:ident => $e:expr),+) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub enum $Name {
            $($n),+
        }

        impl $Name {
            pub fn to_int(&self) -> i32 {
                match *self {
                    $($Name::$n => $e ),+
                }
            }
        }
    }
}
