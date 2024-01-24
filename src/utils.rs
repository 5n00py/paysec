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
}
