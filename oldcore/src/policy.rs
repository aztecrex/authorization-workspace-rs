//! Policy configurations.

use super::dependent_effect::*;
use super::effect::*;
use super::matcher::*;

/// A configured authorization policy.
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy<RMatch, AMatch, CExp> {
    /// Applies if resource and action match but does not depend
    /// on a condition. If matched, it evaluates to `CompputedEffect::Fixed(_)`.
    Unconditional(RMatch, AMatch, Effect),

    /// Applies if resource and action match and result is conditional on environment.
    /// If matched, it evaluates to `ComputedEffect::Atomic(_)`.
    Conditional(RMatch, AMatch, Effect, CExp),

    /// Always applies. It evaluates to `ConditionalEffect::Aggregate(_)`.
    Aggregate(Vec<Policy<RMatch, AMatch, CExp>>),
}

impl<R, RMatch, A, AMatch, CExp> Policy<RMatch, AMatch, CExp>
where
    RMatch: Matcher<Target = R>,
    AMatch: Matcher<Target = A>,
{
    /// Private helper
    fn applies(&self, resource: &R, action: &A) -> bool {
        use Policy::*;

        match self {
            Conditional(rmatch, amatch, _, _) => rmatch.test(&resource) && amatch.test(&action),
            Unconditional(rmatch, amatch, _) => rmatch.test(&resource) && amatch.test(&action),
            Aggregate(_) => true,
        }
    }

    /// Apply policy to a concrete resource and action. Results in a `ComputedEffect` that
    /// can be evaluated in an environment.
    pub fn apply(self, resource: &R, action: &A) -> DependentEffect<CExp> {
        use Policy::*;

        if self.applies(resource, action) {
            match self {
                Conditional(_, _, eff, cond) => DependentEffect::Atomic(eff, cond),
                Unconditional(_, _, eff) => DependentEffect::Fixed(eff),
                Aggregate(ts) => DependentEffect::Aggregate(
                    ts.into_iter().map(|t| t.apply(resource, action)).collect(),
                ),
            }
        } else {
            DependentEffect::Silent
        }
    }
}

/// Apply multiple policies using a strict algorithm. This is used when evaluating
/// policies for a composite principal (e.g. application + user) where authorization
/// requires all consitutents to be authorized.
pub fn apply_disjoint<R, A, Iter, CExp, RMatch, AMatch>(
    policies: Iter,
    resource: &R,
    action: &A,
) -> DependentEffect<CExp>
where
    Iter: IntoIterator<Item = Policy<RMatch, AMatch, CExp>>,
    RMatch: Matcher<Target = R>,
    AMatch: Matcher<Target = A>,
{
    DependentEffect::Disjoint(
        policies
            .into_iter()
            .map(|p| p.apply(resource, action))
            .collect(),
    )
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::action::*;
    use crate::resource::*;

    #[derive(Clone, Copy)]
    pub struct Matcher(&'static str);

    static MATCH_R: StrResource = StrResource("r");
    static MISS_R: StrResource = StrResource("miss");
    static MATCH_A: StrAction = StrAction("a");
    static MATCH_MISS: StrAction = StrAction("miss");

    #[test]
    fn test_unconditional_match_allow() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_A, Effect::ALLOW);

        let actual = policy.apply(&"r".into(), &"a".into());

        assert_eq!(actual, DependentEffect::Fixed(Effect::ALLOW));
    }

    #[test]
    fn test_unconditional_match_deny() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_A, Effect::DENY);

        let actual = policy.apply(&"r".into(), &"a".into());

        assert_eq!(actual, DependentEffect::Fixed(Effect::DENY));
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let policy = Policy::<_, _, ()>::Unconditional(MISS_R, MATCH_A, Effect::DENY);

        let actual = policy.apply(&"r".into(), &"a".into());

        assert_eq!(actual, DependentEffect::Silent);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_MISS, Effect::DENY);

        let actual = policy.apply(&"r".into(), &"a".into());

        assert_eq!(actual, DependentEffect::Silent);
    }

    #[test]
    fn test_conditional_matched_allow() {
        let policy = Policy::Conditional(MATCH_R, MATCH_A, Effect::ALLOW, ());

        let actual = policy.apply(&"r".into(), &"a".into());

        assert_eq!(actual, DependentEffect::Atomic(Effect::ALLOW, ()));
    }

    #[test]
    fn test_aggregate() {
        let match_r1: StrResource = "r1".into();
        let match_r2: StrResource = "r2".into();
        let match_a1: StrAction = "a1".into();
        let match_a2: StrAction = "a2".into();
        let terms = vec![
            Policy::Conditional(match_r1, match_a1, Effect::ALLOW, ()),
            Policy::Conditional(match_r2, match_a1, Effect::ALLOW, ()),
            Policy::Conditional(match_r1, match_a2, Effect::ALLOW, ()),
            Policy::Conditional(match_r2, match_a2, Effect::ALLOW, ()),
            Policy::Unconditional(match_r1, match_a1, Effect::ALLOW),
            Policy::Unconditional(match_r2, match_a1, Effect::ALLOW),
            Policy::Unconditional(match_r1, match_a2, Effect::ALLOW),
            Policy::Unconditional(match_r2, match_a2, Effect::ALLOW),
            Policy::Aggregate(vec![
                Policy::Conditional(match_r1, match_a1, Effect::ALLOW, ()),
                Policy::Conditional(match_r2, match_a1, Effect::ALLOW, ()),
                Policy::Conditional(match_r1, match_a2, Effect::ALLOW, ()),
                Policy::Conditional(match_r2, match_a2, Effect::ALLOW, ()),
                Policy::Unconditional(match_r1, match_a1, Effect::ALLOW),
                Policy::Unconditional(match_r2, match_a1, Effect::ALLOW),
                Policy::Unconditional(match_r1, match_a2, Effect::ALLOW),
                Policy::Unconditional(match_r2, match_a2, Effect::ALLOW),
            ]),
        ];
        let policy = Policy::Aggregate(terms.clone());

        let actual = policy.apply(&"r1".into(), &"a1".into());
        assert_eq!(
            actual,
            DependentEffect::Aggregate(
                terms
                    .iter()
                    .map(|p| p.clone().apply(&"r1".into(), &"a1".into()))
                    .collect()
            )
        );
    }

    #[test]
    fn test_disjoint() {
        let policies = vec![
            Policy::Conditional(MATCH_R, MATCH_A, Effect::ALLOW, 18),
            Policy::Conditional(MATCH_R, MATCH_A, Effect::DENY, 19),
            Policy::Unconditional(MATCH_R, MATCH_A, Effect::ALLOW),
            Policy::Unconditional(MATCH_R, MATCH_A, Effect::DENY),
            Policy::Conditional(MATCH_R, MATCH_MISS, Effect::ALLOW, 20),
            Policy::Conditional(MISS_R, MATCH_A, Effect::DENY, 21),
            Policy::Unconditional(MISS_R, MATCH_A, Effect::ALLOW),
            Policy::Unconditional(MATCH_R, MATCH_MISS, Effect::DENY),
            Policy::Aggregate(vec![Policy::Aggregate(vec![
                Policy::Conditional(MATCH_R, MATCH_A, Effect::ALLOW, 18),
                Policy::Conditional(MATCH_R, MATCH_A, Effect::DENY, 19),
                Policy::Unconditional(MATCH_R, MATCH_A, Effect::ALLOW),
                Policy::Unconditional(MATCH_R, MATCH_A, Effect::DENY),
                Policy::Conditional(MATCH_R, MATCH_MISS, Effect::ALLOW, 20),
                Policy::Conditional(MISS_R, MATCH_A, Effect::DENY, 21),
                Policy::Unconditional(MISS_R, MATCH_A, Effect::ALLOW),
                Policy::Unconditional(MATCH_R, MATCH_MISS, Effect::DENY),
            ])]),
        ];
        let r = "r".into();
        let a = "a".into();

        let actual = apply_disjoint(policies.clone(), &r, &a);

        let expected = DependentEffect::Disjoint(
            policies
                .iter()
                .map(|p| p.clone().apply(&"r".into(), &"a".into()))
                .collect(),
        );
        assert_eq!(actual, expected);
    }
}
