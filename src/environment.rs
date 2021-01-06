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

/// Environment in which conditions always match and evaluations never fail.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct PositiveEnvironment;
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct PositiveEnvironmentError;

impl Environment for PositiveEnvironment {
    type Err = PositiveEnvironmentError;
    type CExp = ();

    fn test_condition(&self, _: &Self::CExp) -> Result<bool, Self::Err> {
        Ok(true)
    }
}

/// Environment in which conditions never match and evaluations never fail.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct NegativeEnvironment;
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct NegativeEnvironmentError;

impl Environment for NegativeEnvironment {
    type Err = NegativeEnvironmentError;
    type CExp = ();

    fn test_condition(&self, _: &Self::CExp) -> Result<bool, Self::Err> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_positive_environment_matches() {
        let env = &PositiveEnvironment;
        assert_eq!(env.test_condition(&()), Ok(true));
    }

    #[test]
    pub fn test_negate_environment_does_not_match() {
        let env = &NegativeEnvironment;
        assert_eq!(env.test_condition(&()), Ok(false));
    }
}
