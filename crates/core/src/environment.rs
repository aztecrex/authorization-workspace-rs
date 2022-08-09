//! Context for authorization resolution.
//!
//!

use std::borrow::Borrow;

/// Contextual computations. An environment is considered unreliable generally
/// so its methods return a `Result` for error signaling.
pub trait Environment {
    /// The type of conditional expression that can be evaluated in the environment.
    type CExp;

    /// Test that a condition holds with respect to the environment. Can return
    fn evaluate<Exp>(&self, exp: Exp) -> bool
    where
        Exp: Borrow<Self::CExp>;
}

pub trait FallibleEnvironment {
    type CExp;
    type Err;

    fn fallible_evaluate<Exp>(&self, exp: Exp) -> Result<bool, Self::Err>
    where
        Exp: Borrow<Self::CExp>;
}

/// Enironment for which expressions always evaluate true.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub struct PositiveEnvironment<CExp = ()>(std::marker::PhantomData<CExp>);

impl PositiveEnvironment {
    /// Create a new positive environment.
    pub fn new() -> Self {
        PositiveEnvironment::default()
    }
}
impl<CExp> Environment for PositiveEnvironment<CExp> {
    type CExp = CExp;

    fn evaluate<Exp>(&self, _exp: Exp) -> bool
    where
        Exp: Borrow<Self::CExp>,
    {
        true
    }
}

/// Enironment for which expressions always evaluate false.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub struct NegativeEnvironment<CExp = ()>(std::marker::PhantomData<CExp>);

impl<CExp> Environment for NegativeEnvironment<CExp> {
    type CExp = CExp;

    fn evaluate<Exp>(&self, _exp: Exp) -> bool
    where
        Exp: Borrow<Self::CExp>,
    {
        false
    }
}

pub struct TrivialEnv;

impl Environment for TrivialEnv {
    type CExp = bool;

    fn evaluate<Exp>(&self, exp: Exp) -> bool
    where
        Exp: Borrow<Self::CExp>,
    {
        *exp.borrow()
    }
}
impl FallibleEnvironment for TrivialEnv {
    type CExp = bool;

    type Err = ();

    fn fallible_evaluate<Exp>(&self, exp: Exp) -> Result<bool, Self::Err>
    where
        Exp: Borrow<Self::CExp>,
    {
        Ok(*exp.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_positive_environment_matches() {
        let env = PositiveEnvironment::default();
        assert!(env.evaluate(()));
    }

    #[test]
    pub fn test_negative_environment_does_not_match() {
        let env = NegativeEnvironment::default();
        assert!(!env.evaluate(()));
    }
}
