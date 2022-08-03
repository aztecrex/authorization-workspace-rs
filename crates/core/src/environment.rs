//! Context for authorization resolution.
//!
//!

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

/// Contextual computations for environments that cannot fail when testing conditions.
pub trait ReliableEnvironment {
    /// The type of conditional expression that can be evaluated in the environment.
    type CExp;

    /// Test that a condition holds with respect to the environment.
    fn reliably_test_condition(&self, exp: &Self::CExp) -> bool;
}

impl<T> Environment for T
where
    T: ReliableEnvironment,
{
    type CExp = <Self as ReliableEnvironment>::CExp;
    type Err = ();

    fn test_condition(&self, exp: &Self::CExp) -> Result<bool, Self::Err> {
        Ok(self.reliably_test_condition(exp))
    }
}

/// Environment in which conditions always match and evaluations never fail.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct PositiveEnvironment;

impl ReliableEnvironment for PositiveEnvironment {
    type CExp = ();

    fn reliably_test_condition(&self, _: &Self::CExp) -> bool {
        true
    }
}

/// Environment in which conditions never match and evaluations never fail.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct NegativeEnvironment;

impl ReliableEnvironment for NegativeEnvironment {
    type CExp = ();
    fn reliably_test_condition(&self, _: &Self::CExp) -> bool {
        false
    }
}

/// Environment in which evaluation always fails
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct FailingEnvironment<Err>(Err);

impl<E> Environment for FailingEnvironment<E>
where
    E: Clone,
{
    type CExp = ();
    type Err = E;

    fn test_condition(&self, _: &Self::CExp) -> Result<bool, Self::Err> {
        Err(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_positive_environment_reliably_matches() {
        let env = &PositiveEnvironment;
        assert_eq!(env.reliably_test_condition(&()), true);
    }

    #[test]
    pub fn test_negate_environment_reliably_does_not_match() {
        let env = &NegativeEnvironment;
        assert_eq!(env.reliably_test_condition(&()), false);
    }
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

    #[test]
    pub fn test_failing_environment_fails() {
        let env = &FailingEnvironment("Whoops");
        assert_eq!(env.test_condition(&()), Err("Whoops"));
    }
}
