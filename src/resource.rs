use super::matcher::*;

/// Trait for matching resources. When evaluating a policy, this is used to determine if
/// the policy applies with respect to a concrete resource.
pub trait ResourceMatch {
    /// The type of resource that can be matched.
    type Resource;

    /// Determine if a concrete resource matches
    fn test(&self, resource: &Self::Resource) -> bool;
}

/// Trivial resource represented by a string. Can also be used as a matcher.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct StrResource<'a>(pub &'a str);

impl<'a> StrResource<'a> {
    pub fn new(v: &'a str) -> Self {
        StrResource(v)
    }
}

impl<'a> From<&'a str> for StrResource<'a> {
    fn from(v: &'a str) -> Self {
        StrResource(v)
    }
}
impl<'a> Matcher for StrResource<'a> {
    type Target = Self;

    fn test(&self, target: &Self::Target) -> bool {
        self.0 == target.0
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_str_resource_matcher() {
        let resource = StrResource("abc");

        assert_eq!(StrResource("abc").test(&resource), true);
        assert_eq!(StrResource("xyz").test(&resource), false);
    }
}
