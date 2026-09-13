use std::fmt::{Debug, Formatter};

use zeroize::Zeroizing;

use crate::PinBlockError;

/// A validated plaintext PIN.
///
/// `Pin` represents a PIN consisting of 4 to 12 ASCII decimal digits.
///
/// The type provides basic in-process protection for plaintext PIN data:
///
/// - PIN contents are redacted from [`Debug`] output,
/// - the owned string is zeroized when dropped,
/// - plaintext digits are available only through an explicit
///   [`Pin::expose_secret`] call.
///
/// # Security
///
/// `Pin` provides defense in depth against accidental disclosure and residual
/// process-memory contents. It does not guarantee that the PIN has never
/// existed elsewhere in memory. For example, callers may retain an original
/// input string, and operating-system facilities such as swap, crash dumps,
/// or process-memory inspection are outside the scope of this type.
pub struct Pin {
    digits: Zeroizing<String>,
}

impl Pin {
    /// Create a validated PIN.
    ///
    /// The supplied PIN must contain between 4 and 12 ASCII decimal digits.
    ///
    /// Passing an owned [`String`] transfers that allocation directly into
    /// the `Pin`, avoiding an additional copy.
    ///
    /// # Errors
    ///
    /// Returns [`PinBlockError::InvalidPin`] if the value is not between
    /// 4 and 12 ASCII decimal digits.
    pub fn new(pin: impl Into<String>) -> Result<Self, PinBlockError> {
        let pin = pin.into();

        if !(4..=12).contains(&pin.len()) || !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err(PinBlockError::InvalidPin);
        }

        Ok(Self {
            digits: Zeroizing::new(pin),
        })
    }

    /// Explicitly expose the plaintext PIN digits.
    ///
    /// This method is intentionally named to make plaintext PIN access
    /// visible during code review.
    pub fn expose_secret(&self) -> &str {
        self.digits.as_str()
    }

    /// Return the PIN length without exposing its digits.
    pub fn len(&self) -> usize {
        self.digits.len()
    }

    /// Return whether the PIN is empty.
    ///
    /// A valid `Pin` can never be empty, but this method is provided for
    /// consistency with other secret-bearing value types.
    pub fn is_empty(&self) -> bool {
        self.digits.is_empty()
    }
}

impl Debug for Pin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pin([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_accepts_valid_digits() {
        let pin = Pin::new("1234").unwrap();

        assert_eq!(pin.expose_secret(), "1234",);

        assert_eq!(pin.len(), 4,);
    }

    #[test]
    fn pin_rejects_too_short_value() {
        assert!(matches!(Pin::new("123"), Err(PinBlockError::InvalidPin)));
    }

    #[test]
    fn pin_rejects_too_long_value() {
        assert!(matches!(
            Pin::new("1234567890123"),
            Err(PinBlockError::InvalidPin)
        ));
    }

    #[test]
    fn pin_rejects_non_ascii_digits() {
        assert!(matches!(Pin::new("12A4"), Err(PinBlockError::InvalidPin)));
    }

    #[test]
    fn pin_debug_is_redacted() {
        let pin = Pin::new("1234").unwrap();

        assert_eq!(format!("{pin:?}"), "Pin([REDACTED])",);
    }
}
