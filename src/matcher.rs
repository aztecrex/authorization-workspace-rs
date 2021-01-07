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
    type Matcher: Matcher<Target = Self::Target>;

    fn match_exact(target: Self::Target) -> Self::Matcher;
    fn match_any<I>(targets: I) -> Self::Matcher
    where
        I: IntoIterator<Item = Self::Target>;
    fn match_all() -> Self::Matcher;
    fn match_none() -> Self::Matcher;
}
