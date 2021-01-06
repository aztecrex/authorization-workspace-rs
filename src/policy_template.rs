use super::authorization::Effect;
use super::policy::*;

pub trait Template<T> {
    type Param;
    fn apply(self, p: &Self::Param) -> T;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyTemplate<RMatchTpl, AMatch, CExp> {
    Unconditional(RMatchTpl, AMatch, Effect),
    Conditional(RMatchTpl, AMatch, Effect, CExp),
    Aggregate(Vec<PolicyTemplate<RMatchTpl, AMatch, CExp>>),
}

impl<Param, RMatchTpl, RMatch, AMatch, CExp> Template<Policy<RMatch, AMatch, CExp>>
    for PolicyTemplate<RMatchTpl, AMatch, CExp>
where
    RMatchTpl: Template<RMatch, Param = Param>,
{
    type Param = Param;
    fn apply(self, p: &Self::Param) -> Policy<RMatch, AMatch, CExp> {
        use PolicyTemplate::*;
        match self {
            Aggregate(elems) => {
                let policy = elems.into_iter().map(|e| e.apply(p)).collect();
                Policy::Aggregate(policy)
            }
            Unconditional(rmtpl, am, eff) => Policy::Unconditional(rmtpl.apply(p), am, eff),
            Conditional(rmtpl, am, eff, cond) => Policy::Conditional(rmtpl.apply(p), am, eff, cond),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /* Don't care that these are real matchers and conditions. just need something to verify the move
    from template to policy
     */
    #[derive(Debug, PartialEq, Eq, Clone)]
    struct RMatch(&'static str);

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct AMatch(&'static str);

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct Cond(&'static str);

    #[derive(Clone, Copy)]
    struct RMatchTpl;
    impl Template<RMatch> for RMatchTpl {
        type Param = &'static str;
        fn apply(self, p: &Self::Param) -> RMatch {
            RMatch(p)
        }
    }

    #[test]
    fn test_empty_aggregate() {
        let template = PolicyTemplate::<RMatchTpl, AMatch, Cond>::Aggregate(vec![]);

        let actual = template.apply(&"not important");

        assert_eq!(actual, Policy::Aggregate(vec![]));
    }

    #[test]
    fn test_nonempty_aggregate() {
        use PolicyTemplate::*;
        let elems = vec![
            Unconditional(RMatchTpl, AMatch("a1"), Effect::ALLOW),
            Unconditional(RMatchTpl, AMatch("a2"), Effect::DENY),
            Conditional(RMatchTpl, AMatch("a3"), Effect::ALLOW, Cond("c1")),
            Conditional(RMatchTpl, AMatch("a4"), Effect::DENY, Cond("c2")),
            Aggregate(vec![
                Aggregate(vec![
                    Unconditional(RMatchTpl, AMatch("a5"), Effect::ALLOW),
                    Unconditional(RMatchTpl, AMatch("a6"), Effect::DENY),
                    Conditional(RMatchTpl, AMatch("a7"), Effect::ALLOW, Cond("c3")),
                    Conditional(RMatchTpl, AMatch("a8"), Effect::DENY, Cond("c4")),
                ]),
                Aggregate(vec![]),
            ]),
        ];
        let template = Aggregate(elems.clone());

        let actual = template.apply(&"param");

        let expected = elems.into_iter().map(|e| e.apply(&"param")).collect();
        let expected = Policy::Aggregate(expected);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_unconditional_allow() {
        let rmatch_tpl = RMatchTpl;
        let template = PolicyTemplate::<RMatchTpl, AMatch, Cond>::Unconditional(
            rmatch_tpl,
            AMatch("a"),
            Effect::ALLOW,
        );

        let actual = template.apply(&"xyz");

        assert_eq!(
            actual,
            Policy::Unconditional(rmatch_tpl.apply(&"xyz"), AMatch("a"), Effect::ALLOW)
        );
    }

    #[test]
    fn test_unconditional_deny() {
        let rmatch_tpl = RMatchTpl;
        let template = PolicyTemplate::<RMatchTpl, AMatch, Cond>::Unconditional(
            rmatch_tpl,
            AMatch("a"),
            Effect::DENY,
        );

        let actual = template.apply(&"xyz");

        assert_eq!(
            actual,
            Policy::Unconditional(rmatch_tpl.apply(&"xyz"), AMatch("a"), Effect::DENY)
        );
    }

    #[test]
    fn test_conditional_allow() {
        let rmatch_tpl = RMatchTpl;
        let template = PolicyTemplate::<RMatchTpl, AMatch, Cond>::Conditional(
            rmatch_tpl,
            AMatch("a"),
            Effect::ALLOW,
            Cond("c"),
        );

        let actual = template.apply(&"xyz");

        assert_eq!(
            actual,
            Policy::Conditional(
                rmatch_tpl.apply(&"xyz"),
                AMatch("a"),
                Effect::ALLOW,
                Cond("c")
            )
        );
    }

    #[test]
    fn test_conditional_deny() {
        let rmatch_tpl = RMatchTpl;
        let template = PolicyTemplate::<RMatchTpl, AMatch, Cond>::Conditional(
            rmatch_tpl,
            AMatch("a"),
            Effect::DENY,
            Cond("x"),
        );

        let actual = template.apply(&"xyz");

        assert_eq!(
            actual,
            Policy::Conditional(
                rmatch_tpl.apply(&"xyz"),
                AMatch("a"),
                Effect::DENY,
                Cond("x")
            )
        );
    }
}
