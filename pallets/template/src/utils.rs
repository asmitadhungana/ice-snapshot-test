///! Helper collections of utilities to support lib.rs
use frame_support::pallet_prelude::*;

#[macro_export]

/// This macro will log the formatted message with
/// eprintln when testing othwerwise with log::debug
macro_rules! report {
	// Match the formatter with formatting paramater
	($formatter: literal, $($args: expr),*) => {
		#[cfg(test)]
		eprintln!($formatter, $($args),*);

		#[cfg(not(test))]
		log::debug!($formatter, $($args),*);
	};

	// match the literal only syntax
	($formatter: literal) => {
		report!($formatter, );
	}
}

#[derive(Encode, Decode, RuntimeDebug, scale_info::TypeInfo)]
pub enum RequestStatus {
    Granted,
    Pending,
}

impl Default for RequestStatus {
    fn default() -> Self {
        RequestStatus::Pending
    }
}
