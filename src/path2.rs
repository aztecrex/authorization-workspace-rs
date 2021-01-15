use super::matcher::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Path2Elem<'a>(&'a str);

impl<'a, I> From<I> for Path2Elem<'a>
where
    I: Into<&'a str>,
{
    fn from(v: I) -> Self {
        Path2Elem(v.into())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Path2ElemMatcher<'a> {
    ANY,
    NONE,
    V(&'a str),
}

impl <'a> Path2ElemMatcher<'a> {
    pub fn new<V>(v: V) -> Path2ElemMatcher<'a>
    where
        V: Into<&'a str>,
    {
        Path2ElemMatcher::V(v.into())
    }
}

impl<'a, I> From<I> for Path2ElemMatcher<'a>
where
    I: Into<&'a str>,
{
    fn from(v: I) -> Self {
        Path2ElemMatcher::new(v)
    }
}

impl <'a> From<Path2Elem<'a>> for Path2ElemMatcher<'a> {
    fn from(v: Path2Elem<'a>) -> Self {
        Path2ElemMatcher::new(v.0)
    }
}

impl <'a> Matcher for Path2ElemMatcher<'a> {
    type Target = Path2Elem<'a>;

    fn test(&self, target: &Self::Target) -> bool {
        use Path2ElemMatcher::*;
        match self {
            ANY => true,
            NONE => false,
            V(s) => s == &target.0,
        }
    }
}

impl <'a> ExtendedMatcher for Path2ElemMatcher<'a> {
    type Target = Path2Elem<'a>;

    /// Match a specific resource
    fn match_only<T: Into<Self::Target>>(target: T) -> Self {
        target.into().into()
    }

    /// Match any resouorce (i.e. test is const true)
    fn match_any() -> Self {
        Path2ElemMatcher::ANY
    }

    /// match nothing (i.e. test is const false)
    fn match_none() -> Self {
        Path2ElemMatcher::NONE
    }
}

// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct Path(Vec<PathElem>);

// impl Path {
//     pub fn new<I, E>(elems: I) -> Self
//     where
//         E: Into<PathElem>,
//         I: IntoIterator<Item = E>,
//     {
//         Path(elems.into_iter().map(|e| e.into()).collect())
//     }
// }

// impl<I, E> From<I> for Path
// where
//     E: Into<PathElem>,
//     I: IntoIterator<Item = E>,
// {
//     fn from(elems: I) -> Self {
//         Path::new(elems)
//     }
// }

// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct PathMatcher(Vec<PathElemMatcher>);

// impl PathMatcher {
//     pub fn new<I, E>(elems: I) -> Self
//     where
//         E: Into<PathElemMatcher>,
//         I: IntoIterator<Item = E>,
//     {
//         PathMatcher(elems.into_iter().map(|e| e.into()).collect())
//     }
// }

// impl<I, E> From<I> for PathMatcher
// where
//     E: Into<PathElemMatcher>,
//     I: IntoIterator<Item = E>,
// {
//     fn from(elems: I) -> Self {
//         PathMatcher::new(elems)
//     }
// }

// impl From<Path> for PathMatcher {
//     fn from(path: Path) -> Self {
//         let Path(path) = path;
//         PathMatcher(path.into_iter().map(|e| e.into()).collect())
//     }
// }

// impl Matcher for PathMatcher {
//     type Target = Path;
//     fn test(&self, target: &Self::Target) -> bool {
//         self.0.len() == target.0.len() && self.0.iter().zip(target.0.iter()).all(|(m, e)| m.test(e))
//     }
// }

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_path_elem_matcher_any() {
        let e = Path2ElemMatcher::ANY;

        let actual = e.test(&"totally arbitrary".into());

        assert_eq!(actual, true);
    }

    #[test]
    fn test_path_elem_matcher_none() {
        let e = Path2ElemMatcher::NONE;

        let actual = e.test(&"totally arbitrary".into());

        assert_eq!(actual, false);
    }

    #[test]
    fn test_path_elem_matcher_v() {
        let matcher = Path2ElemMatcher::V("matchit");

        let actual = matcher.test(&"matchit".into());
        assert_eq!(actual, true);

        let actual = matcher.test(&"arbitrary".into());
        assert_eq!(actual, false);
    }

    #[test]
    fn test_path_elem_ext_match_only() {
        let matcher = Path2ElemMatcher::match_only("matchit");

        let equivalent = Path2ElemMatcher::V("matchit");

        let actual = matcher.test(&"matchit".into());
        let expected = equivalent.test(&"matchit".into());
        assert_eq!(actual, expected);

        let actual = matcher.test(&"other".into());
        let expected = equivalent.test(&"other".into());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_path_elem_ext_match_any() {
        let matcher = Path2ElemMatcher::match_any();

        let equivalent = Path2ElemMatcher::ANY;

        let actual = matcher.test(&"arbitrary".into());
        let expected = equivalent.test(&"arbitrary".into());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_path_elem_ext_match_none() {
        let matcher = Path2ElemMatcher::match_none();

        let equivalent = Path2ElemMatcher::NONE;

        let actual = matcher.test(&"arbitrary".into());
        let expected = equivalent.test(&"arbitrary".into());
        assert_eq!(actual, expected);
    }

//     #[test]
//     /// basic happy path
//     fn test_path_match_all_exact() {
//         let positive = Path::new(vec!["a", "b", "c"]);
//         let matcher: PathMatcher = positive.clone().into();
//         let negative = Path::new(vec!["a", "b", "z"]);

//         assert_eq!(matcher.test(&positive), true);
//         assert_eq!(matcher.test(&negative), false);
//     }

//     #[test]
//     fn test_path_match_with_wild() {
//         let matcher = PathMatcher::new(vec![
//             PathElemMatcher::new("a"),
//             PathElemMatcher::ANY,
//             PathElemMatcher::new("c"),
//         ]);

//         let p1 = vec!["a", "b", "c"].into();
//         let p2 = vec!["a", "z", "c"].into();
//         let p3 = vec!["z", "b", "c"].into();

//         assert_eq!(matcher.test(&p1), true);
//         assert_eq!(matcher.test(&p2), true);
//         assert_eq!(matcher.test(&p3), false);
//     }

//     #[test]
//     fn test_path_matcher_mismatched_aize() {
//         let matcher = PathMatcher::new(vec![
//             PathElemMatcher::new("a"),
//             PathElemMatcher::new("b"),
//             PathElemMatcher::new("c"),
//         ]);

//         let p1 = vec!["a", "b", "c"].into();
//         let p2 = vec!["a", "b"].into();
//         let p3 = vec!["a", "b", "c", "d"].into();

//         assert_eq!(matcher.test(&p1), true);
//         assert_eq!(matcher.test(&p2), false);
//         assert_eq!(matcher.test(&p3), false);
//     }
}
