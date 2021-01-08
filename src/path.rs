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

impl PathElemMatcher {
    pub fn new<V>(v: V) -> PathElemMatcher
    where
        V: Into<String>,
    {
        PathElemMatcher::V(v.into())
    }
}

impl<I> From<I> for PathElemMatcher
where
    I: Into<String>,
{
    fn from(v: I) -> Self {
        PathElemMatcher::new(v)
    }
}

impl From<PathElem> for PathElemMatcher {
    fn from(v: PathElem) -> Self {
        let PathElem(v) = v;
        PathElemMatcher::new(v)
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Path(Vec<PathElem>);

impl Path {
    pub fn new<I, E>(elems: I) -> Self
    where
        E: Into<PathElem>,
        I: IntoIterator<Item = E>,
    {
        Path(elems.into_iter().map(|e| e.into()).collect())
    }
}

impl<I, E> From<I> for Path
where
    E: Into<PathElem>,
    I: IntoIterator<Item = E>,
{
    fn from(elems: I) -> Self {
        Path::new(elems)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PathMatcher(Vec<PathElemMatcher>);

impl PathMatcher {
    pub fn new<I, E>(elems: I) -> Self
    where
        E: Into<PathElemMatcher>,
        I: IntoIterator<Item = E>,
    {
        PathMatcher(elems.into_iter().map(|e| e.into()).collect())
    }
}

impl<I, E> From<I> for PathMatcher
where
    E: Into<PathElemMatcher>,
    I: IntoIterator<Item = E>,
{
    fn from(elems: I) -> Self {
        PathMatcher::new(elems)
    }
}

impl From<Path> for PathMatcher {
    fn from(path: Path) -> Self {
        let Path(path) = path;
        PathMatcher(path.into_iter().map(|e| e.into()).collect())
    }
}

impl Matcher for PathMatcher {
    type Target = Path;
    fn test(&self, target: &Self::Target) -> bool {
        self.0.iter().zip(target.0.iter()).all(|(m, e)| m.test(e))
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

    #[test]
    /// basic happy path
    fn test_path_match_all_exact() {
        let positive = Path::new(vec!["a", "b", "c"]);
        let matcher: PathMatcher = positive.clone().into();
        let negative = Path::new(vec!["a", "b", "z"]);

        assert_eq!(matcher.test(&positive), true);
        assert_eq!(matcher.test(&negative), false);
    }

    #[test]
    fn test_path_match_with_wild() {
        let matcher = PathMatcher::new(vec![
            PathElemMatcher::new("a"),
            PathElemMatcher::ANY,
            PathElemMatcher::new("c"),
        ]);

        let p1 = vec!["a", "b", "c"].into();
        let p2 = vec!["a", "z", "c"].into();
        let p3 = vec!["z", "b", "c"].into();

        assert_eq!(matcher.test(&p1), true);
        assert_eq!(matcher.test(&p2), true);
        assert_eq!(matcher.test(&p3), false);
    }
}
