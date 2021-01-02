use super::conditional_effect::*;
use super::effect::*;

pub trait ResourceMatch {
    type Resource;
    fn test(&self, resource: &Self::Resource) -> bool;
}

pub trait ActionMatch {
    type Action;
    fn test(&self, action: &Self::Action) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy<RMatch, AMatch, CExp> {
    Unconditional(RMatch, AMatch, Effect),
    Conditional(RMatch, AMatch, Effect, CExp),
    Aggregate(Vec<Policy<RMatch, AMatch, CExp>>),
}

impl<R, RMatch, A, AMatch, CExp> Policy<RMatch, AMatch, CExp>
where
    RMatch: ResourceMatch<Resource = R>,
    AMatch: ActionMatch<Action = A>,
{
    fn applies(&self, resource: &R, action: &A) -> bool {
        use Policy::*;

        match self {
            Conditional(rmatch, amatch, _, _) => rmatch.test(&resource) && amatch.test(&action),
            Unconditional(rmatch, amatch, _) => rmatch.test(&resource) && amatch.test(&action),
            Aggregate(_) => true,
        }
    }

    pub fn apply(self, resource: &R, action: &A) -> ConditionalEffect<CExp> {
        use Policy::*;

        if self.applies(resource, action) {
            match self {
                Conditional(_, _, eff, cond) => ConditionalEffect::Atomic(eff, cond),
                Unconditional(_, _, eff) => ConditionalEffect::Fixed(eff),
                Aggregate(ts) => ConditionalEffect::Aggregate(
                    ts.into_iter().map(|t| t.apply(resource, action)).collect(),
                ),
            }
        } else {
            ConditionalEffect::Silent
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use Effect::*;

    pub struct Resource(&'static str);
    pub struct Action(&'static str);

    #[derive(Clone, Copy)]
    pub struct Matcher(&'static str);

    static MATCH_R: Matcher = Matcher("r");
    static MATCH_A: Matcher = Matcher("a");
    static MATCH_MISS: Matcher = Matcher("miss");

    impl ResourceMatch for Matcher {
        type Resource = Resource;
        fn test(&self, resource: &Self::Resource) -> bool {
            let Resource(v) = resource;
            let Matcher(m) = self;
            v == m
        }
    }

    impl ActionMatch for Matcher {
        type Action = Action;
        fn test(&self, action: &Self::Action) -> bool {
            let Action(v) = action;
            let Matcher(m) = self;
            v == m
        }
    }

    #[test]
    fn test_unconditional_match_allow() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_A, ALLOW);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Fixed(ALLOW));
    }

    #[test]
    fn test_unconditional_match_deny() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_A, DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Fixed(DENY));
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_MISS, MATCH_A, DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Silent);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_MISS, DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Silent);
    }

    #[test]
    fn test_conditional_matched_allow() {
        let policy = Policy::Conditional(MATCH_R, MATCH_A, ALLOW, ());

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Atomic(ALLOW, ()));
    }

    #[test]
    fn test_aggregate() {
        let match_r1 = Matcher("r1");
        let match_r2 = Matcher("r2");
        let match_a1 = Matcher("a1");
        let match_a2 = Matcher("a2");
        let terms = vec![
            Policy::Conditional(match_r1, match_a1, ALLOW, ()),
            Policy::Conditional(match_r2, match_a1, ALLOW, ()),
            Policy::Conditional(match_r1, match_a2, ALLOW, ()),
            Policy::Conditional(match_r2, match_a2, ALLOW, ()),
            Policy::Unconditional(match_r1, match_a1, ALLOW),
            Policy::Unconditional(match_r2, match_a1, ALLOW),
            Policy::Unconditional(match_r1, match_a2, ALLOW),
            Policy::Unconditional(match_r2, match_a2, ALLOW),
            Policy::Aggregate(vec![
                Policy::Conditional(match_r1, match_a1, ALLOW, ()),
                Policy::Conditional(match_r2, match_a1, ALLOW, ()),
                Policy::Conditional(match_r1, match_a2, ALLOW, ()),
                Policy::Conditional(match_r2, match_a2, ALLOW, ()),
                Policy::Unconditional(match_r1, match_a1, ALLOW),
                Policy::Unconditional(match_r2, match_a1, ALLOW),
                Policy::Unconditional(match_r1, match_a2, ALLOW),
                Policy::Unconditional(match_r2, match_a2, ALLOW),
            ]),
        ];
        let policy = Policy::Aggregate(terms.clone());

        let actual = policy.apply(&Resource("r1"), &Action("a1"));
        assert_eq!(
            actual,
            ConditionalEffect::Aggregate(
                terms
                    .iter()
                    .map(|p| p.clone().apply(&Resource("r1"), &Action("a1")))
                    .collect()
            )
        );
    }
}
