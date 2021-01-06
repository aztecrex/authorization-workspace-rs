//! Side-effectful computation context.

/// Contextual computations. An environment is considered unreliable generally
/// so its methods return a `Result` for error signaling.
pub trait Environment {
    /// The type of error produced by this environmnt e.g. remote communication or databases errors.
    type Err;

    /// The type of conditional expression that can be evaluated in the environment.
    type CExp;

    /// Test that a condition holds with respect to the environment. Can return
    /// `Err(_)` if an environmental error is encountered.
    fn test_condition(&self, exp: &Self::CExp) -> Result<bool, Self::Err>;
}
