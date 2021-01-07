pub trait Matcher {
    /// Type of value that can be matched.
    type Target;

    /// Determine if a concrete target matches
    fn test(&self, target: &Self::Target) -> bool;
}

/// Convenience methods for matchers. Non-trivial matchers should implement
/// this.
pub trait ExtendedMatcher {
    type Target;

    /// Match a specific resource
    fn match_only(target: Self::Target) -> Self;

    /// Match any resouorce (i.e. test is const true)
    fn match_any() -> Self;

    /// match nothing (i.e. test is const false)
    fn match_none() -> Self;
}

// impl <T, M> From<T> for M: ExtendedMatcher<Target = T>
// {
//     fn from(v: T) -> Self {
//         M::match_only(v)
//     }
// }
