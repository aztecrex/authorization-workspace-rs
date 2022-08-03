//! Value matching traits.
//!
//! This could use a better name. The basic funcionality
//! checks values for inclusion in a group. I don't
//! think it's an equivalance class but maybe something
//! along those lines.

/// Basic matcher trait. Represents a class of values
/// for which inclusion can be tested.
pub trait Matcher {
    /// Type of value that can be matched.
    type Target;

    /// Determine if a concrete target matches
    fn test(&self, target: &Self::Target) -> bool;
}

/// Convenience methods for matchers. Non-trivial matchers should implement
/// this.
pub trait ExtendedMatcher: Matcher {
    /// Match a specific resource
    fn match_only(target: <Self as Matcher>::Target) -> Self;

    /// Match any resouorce (i.e. test is const true)
    fn match_any() -> Self;

    /// match nothing (i.e. test is const false)
    fn match_none() -> Self;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Wrapper for direct equality matching.
pub enum EqualityMatcher<T> {
    /// Match a specific value.
    Only(T),
    /// Match any value.
    Any,
    /// Match nothing.
    None,
}

impl<T> From<T> for EqualityMatcher<T> {
    fn from(target: T) -> Self {
        EqualityMatcher::Only(target)
    }
}

impl<T> Matcher for EqualityMatcher<T>
where
    T: Eq,
{
    type Target = T;

    fn test(&self, target: &Self::Target) -> bool {
        match self {
            &EqualityMatcher::Only(ref t) => t == target,
            &EqualityMatcher::Any => true,
            &EqualityMatcher::None => false,
        }
    }
}

impl<T> ExtendedMatcher for EqualityMatcher<T>
where
    EqualityMatcher<T>: Matcher,
    <Self as Matcher>::Target: Into<Self>,
{
    fn match_only(target: <Self as Matcher>::Target) -> Self {
        target.into()
    }

    fn match_any() -> Self {
        EqualityMatcher::Any
    }

    fn match_none() -> Self {
        EqualityMatcher::None
    }
}
