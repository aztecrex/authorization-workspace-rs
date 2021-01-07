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
    V(String)
}

impl<I> From<I> for PathElemMatcher
where
    I: Into<String>,
{
    fn from(v: I) -> Self {
        PathElemMatcher::V(v.into())
    }
}

impl Matcher for PathElemMatcher {
    type Target = PathElem;

    fn test(&self, target: &Self::Target) -> bool {
        use PathElemMatcher::*;
        match self {
            ANY => true,
            NONE => false,
            _ => unimplemented!(),
        }
        
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

}


