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

#[derive(Clone, Debug)]
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

        let (rmatch, amatch) = match self {
            Conditional(rmatch, amatch, _, _) => (rmatch, amatch),
            Unconditional(rmatch, amatch, _) => (rmatch, amatch),
            Aggregate(_) => return true,
        };
        rmatch.test(&resource) && amatch.test(&action)
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

    impl ResourceMatch for &str {
        type Resource = Resource;
        fn test(&self, resource: &Self::Resource) -> bool {
            let Resource(v) = resource;
            v == self
        }
    }

    impl ActionMatch for &str {
        type Action = Action;
        fn test(&self, action: &Self::Action) -> bool {
            let Action(a) = action;
            a == self
        }
    }

    #[test]
    fn test_unconditional_match_allow() {
        let policy = Policy::<_, _, ()>::Unconditional("r", "a", ALLOW);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Fixed(ALLOW));
    }

    #[test]
    fn test_unconditional_match_deny() {
        let policy = Policy::<_, _, ()>::Unconditional("r", "a", DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Fixed(DENY));
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let policy = Policy::<_, _, ()>::Unconditional("miss", "a", DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Silent);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let policy = Policy::<_, _, ()>::Unconditional("r", "miss", DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Silent);
    }

    #[test]
    fn test_conditional_matched_allow() {
        let policy = Policy::Conditional("r", "a", ALLOW, ());

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, ConditionalEffect::Atomic(ALLOW, ()));
    }

    #[test]
    fn test_aggregate() {
        let terms = vec![
            Policy::Conditional("r1", "a1", ALLOW, ()),
            Policy::Conditional("r2", "a1", ALLOW, ()),
            Policy::Conditional("r1", "a2", ALLOW, ()),
            Policy::Conditional("r2", "a2", ALLOW, ()),
            Policy::Unconditional("r1", "a1", ALLOW),
            Policy::Unconditional("r2", "a1", ALLOW),
            Policy::Unconditional("r1", "a2", ALLOW),
            Policy::Unconditional("r2", "a2", ALLOW),
            Policy::Aggregate(vec![
                Policy::Conditional("r1", "a1", ALLOW, ()),
                Policy::Conditional("r2", "a1", ALLOW, ()),
                Policy::Conditional("r1", "a2", ALLOW, ()),
                Policy::Conditional("r2", "a2", ALLOW, ()),
                Policy::Unconditional("r1", "a1", ALLOW),
                Policy::Unconditional("r2", "a1", ALLOW),
                Policy::Unconditional("r1", "a2", ALLOW),
                Policy::Unconditional("r2", "a2", ALLOW),
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
