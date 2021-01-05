//! Conditions as environmental side effects

/// An environment in which conditions can be evaluated.
pub trait Environment {
    // The type of error produced by this environmnt e.g. remote communication or databases errors.
    type Err;

    // The type of expression that can be evaluated in the environment.
    type CExp;

    /// Test that a condition holds with respect to the environment. Can return
    /// `Err(_)` if an environmental error is encountered.
    fn test_condition(&self, exp: &Self::CExp) -> Result<bool, Self::Err>;
}
