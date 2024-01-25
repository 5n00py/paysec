/// Perform bitwise XOR operation between two byte arrays of equal length.
///
/// This function takes two byte arrays `a` and `b` and performs a bitwise XOR
/// operation between their elements. The two input arrays must have the same length.
///
/// # Parameters
///
/// * `a`: A reference to the first byte array.
/// * `b`: A reference to the second byte array.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - A new byte array containing the result of the XOR operation.
/// * `Err(String)` - If the input arrays have different lengths.
///
/// # Errors
///
/// This function will return an error if:
/// - The input arrays `a` and `b` have different lengths.
pub fn xor_byte_arrays(a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
    if a.len() != b.len() {
        return Err("Arrays must be of the same length".to_string());
    }

    Ok(a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect())
}

/// Left-pad a string with a specified character up to a given length.
///
/// This function takes a string `input`, a desired `length`, and a `padding_char`.
/// It adds left padding to the string with the provided character up to the given length.
/// If the string is already at or longer than the desired length, it remains unchanged.
///
/// # Parameters
///
/// * `input`: A reference to the input string.
/// * `length`: The desired length after padding.
/// * `padding_char`: The character used for padding.
///
/// # Returns
///
/// * `String` - The input string left-padded to the specified length with the padding character.
pub fn left_pad_str(input: &str, length: usize, padding_char: char) -> String {
    if input.len() >= length {
        input.to_string()
    } else {
        let padding = length - input.len();
        let padding_string: String = std::iter::repeat(padding_char).take(padding).collect();
        padding_string + input
    }
}

/// Right-pad a string with a specified character up to a given length.
///
/// This function takes a string `input`, a desired `length`, and a `padding_char`.
/// It adds right padding to the string with the provided character up to the given length.
/// If the string is already at or longer than the desired length, it remains unchanged.
///
/// # Parameters
///
/// * `input`: A reference to the input string.
/// * `length`: The desired length after padding.
/// * `padding_char`: The character used for padding.
///
/// # Returns
///
/// * `String` - The input string right-padded to the specified length with the padding character.
pub fn right_pad_str(input: &str, length: usize, padding_char: char) -> String {
    if input.len() >= length {
        input.to_string()
    } else {
        let padding = length - input.len();
        let padding_string: String = std::iter::repeat(padding_char).take(padding).collect();
        input.to_string() + &padding_string
    }
}

/// Transform each nibble of the input bytes to the A-F hexadecimal range.
///
/// This function processes each byte in the input slice and transforms its nibbles
/// (4-bit groups) so that they fall within the hexadecimal range of A (10) to F (15).
/// It achieves this by adjusting the values of the nibbles to ensure they are
/// within the desired range. The function is particularly useful in scenarios where
/// hexadecimal representation strictly requires characters in the A-F range.
///
/// # Parameters
///
/// * `input`: A slice of bytes (`&[u8]`) to be transformed.
///
/// # Returns
///
/// A `Vec<u8>` where each byte has its nibbles transformed to the A-F range.
///
pub fn transform_nibbles_to_af(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());

    for &byte in input {
        // Process higher nibble
        let high_nibble = (byte >> 4) & 0x0F;
        let transformed_high = transform_nibble(high_nibble);

        // Process lower nibble
        let low_nibble = byte & 0x0F;
        let transformed_low = transform_nibble(low_nibble);

        // Combine the transformed nibbles back into a byte
        let output_byte = (transformed_high << 4) | transformed_low;
        output.push(output_byte);
    }

    output
}

fn transform_nibble(nibble: u8) -> u8 {
    match nibble {
        0..=5 => nibble + 10, // Transform 0-5 to A-F
        6..=9 => nibble + 6,  // Transform 6-9 to A-F
        _ => nibble,          // Keep A-F as is
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_byte_arrays() {
        // Test case 1: Equal-length arrays, result should be XORed correctly.
        let a = [0b1010, 0b1100, 0b1111];
        let b = [0b0101, 0b0011, 0b1010];
        let expected_result = vec![0b1111, 0b1111, 0b0101];
        assert_eq!(xor_byte_arrays(&a, &b), Ok(expected_result));

        // Test case 2: Arrays with different lengths, should return an error.
        let c = [0b1010, 0b1100];
        assert_eq!(
            xor_byte_arrays(&a, &c),
            Err("Arrays must be of the same length".to_string())
        );
    }

    #[test]
    fn test_left_pad_str() {
        // Test case 1: String is shorter, should left-pad with '0'.
        let input = "123";
        let length = 6;
        let padding_char = '0';
        let expected_result = "000123".to_string();
        assert_eq!(left_pad_str(input, length, padding_char), expected_result);

        // Test case 2: String is already longer, should not change.
        let input2 = "abcdef";
        let length2 = 4;
        let padding_char2 = '-';
        assert_eq!(left_pad_str(input2, length2, padding_char2), input2);
    }

    #[test]
    fn test_right_pad_str() {
        // Test case 1: String is shorter, should right-pad with '0'.
        let input = "123";
        let length = 6;
        let padding_char = '0';
        let expected_result = "123000".to_string();
        assert_eq!(right_pad_str(input, length, padding_char), expected_result);

        // Test case 2: String is already longer, should not change.
        let input2 = "abcdef";
        let length2 = 4;
        let padding_char2 = '-';
        assert_eq!(right_pad_str(input2, length2, padding_char2), input2);
    }

    #[test]
    fn test_transform_nibbles_to_af() {
        let input = vec![0x45, 0x82, 0x1A, 0xBC, 0x09, 0x34];
        let expected_output = vec![0xEF, 0xEC, 0xBA, 0xBC, 0xAF, 0xDE];

        let result = transform_nibbles_to_af(&input);

        assert_eq!(
            result, expected_output,
            "Nibbles were not correctly transformed to A-F range."
        );
    }
}
