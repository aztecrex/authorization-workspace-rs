use super::effect::Effect;
use super::policy::*;

pub trait Template<T> {
    type Param;
    fn apply(self, p: Self::Param) -> T;
}

pub enum PolicyTemplate<RMatchTpl, AMatch, CExp> {
    // Unconditional(RMatchTpl, AMatch, Effect),
    // Conditional(RMatchTpl, AMatch, Effect, CExp),
    Aggregate(Vec<Policy<RMatchTpl, AMatch, CExp>>),
}

impl<Param, RMatchTpl, RMatch, AMatch, CExp> Template<Policy<RMatch, AMatch, CExp>>
    for PolicyTemplate<RMatchTpl, AMatch, CExp>
where
    RMatchTpl: Template<RMatch, Param = Param>,
{
    type Param = Param;
    fn apply(self, _p: Self::Param) -> Policy<RMatch, AMatch, CExp> {
        Policy::Aggregate(vec![])
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /* Don't care that these are real matchers and conditions. just need something to verify the move
    from template to policy
     */
    #[derive(Debug, PartialEq, Eq)]
    struct RMatch(&'static str);

    #[derive(Debug, PartialEq, Eq)]
    struct AMatch(&'static str);

    #[derive(Debug, PartialEq, Eq)]
    struct Cond(&'static str);

    struct RMatchTpl;
    impl Template<RMatch> for RMatchTpl {
        type Param = &'static str;
        fn apply(self, _p: Self::Param) -> RMatch {
            unimplemented!();
        }
    }

    #[test]
    fn test_empty_aggregate() {
        let template = PolicyTemplate::<RMatchTpl, AMatch, Cond>::Aggregate(vec![]);

        let actual = template.apply("hello");

        assert_eq!(actual, Policy::Aggregate(vec![]));
    }
}
