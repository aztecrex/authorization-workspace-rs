use super::matcher::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PathElem(String);

impl<I> From<I> for PathElem
where
    I: Into<String>,
{
    fn from(v: I) -> Self {
        PathElem(v.into())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PathElemMatcher {
    ANY,
    NONE,
    V(String),
}

impl<I> From<I> for PathElemMatcher
where
    I: Into<String>,
{
    fn from(v: I) -> Self {
        PathElemMatcher::V(v.into())
    }
}

impl From<PathElem> for PathElemMatcher {
    fn from(v: PathElem) -> Self {
        let PathElem(v) = v;
        PathElemMatcher::V(v)
    }
}

impl Matcher for PathElemMatcher {
    type Target = PathElem;

    fn test(&self, target: &Self::Target) -> bool {
        use PathElemMatcher::*;
        match self {
            ANY => true,
            NONE => false,
            V(s) => s == &target.0,
        }
    }
}

impl ExtendedMatcher for PathElemMatcher {
    type Target = PathElem;

    /// Match a specific resource
    fn match_only(target: Self::Target) -> Self {
        PathElemMatcher::V(target.0.into())
    }

    /// Match any resouorce (i.e. test is const true)
    fn match_any() -> Self {
        PathElemMatcher::ANY
    }

    /// match nothing (i.e. test is const false)
    fn match_none() -> Self {
        PathElemMatcher::NONE
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_path_elem_matcher_any() {
        let e = PathElemMatcher::ANY;

        let actual = e.test(&"totally arbitrary".into());

        assert_eq!(actual, true);
    }

    #[test]
    fn test_path_elem_matcher_none() {
        let e = PathElemMatcher::NONE;

        let actual = e.test(&"totally arbitrary".into());

        assert_eq!(actual, false);
    }

    #[test]
    fn test_path_elem_matcher_v() {
        let matcher = PathElemMatcher::V("matchit".into());

        let actual = matcher.test(&"matchit".into());
        assert_eq!(actual, true);

        let actual = matcher.test(&"arbitrary".into());
        assert_eq!(actual, false);
    }

    #[test]
    fn test_path_elem_ext_match_only() {
        let matcher = PathElemMatcher::match_only("matchit".into());

        let equivalent = PathElemMatcher::V("matchit".into());

        let actual = matcher.test(&"matchit".into());
        let expected = equivalent.test(&"matchit".into());
        assert_eq!(actual, expected);

        let actual = matcher.test(&"other".into());
        let expected = equivalent.test(&"other".into());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_path_elem_ext_match_any() {
        let matcher = PathElemMatcher::match_any();

        let equivalent = PathElemMatcher::ANY;

        let actual = matcher.test(&"arbitrary".into());
        let expected = equivalent.test(&"arbitrary".into());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_path_elem_ext_match_none() {
        let matcher = PathElemMatcher::match_none();

        let equivalent = PathElemMatcher::NONE;

        let actual = matcher.test(&"arbitrary".into());
        let expected = equivalent.test(&"arbitrary".into());
        assert_eq!(actual, expected);
    }
}
