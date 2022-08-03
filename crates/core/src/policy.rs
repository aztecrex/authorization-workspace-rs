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

    /// Applies if resource and action match and the condition applies in the evaluation environment.
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

    type StrMatcher = EqualityMatcher<&'static str>;

    static R: &'static str = "r";
    static R2: &'static str = "r2";
    static A: &'static str = "a";
    static A2: &'static str = "a2";

    struct Matchers {
        m_r: StrMatcher,
        m_r2: StrMatcher,
        m_a: StrMatcher,
        m_a2: StrMatcher,
        miss: StrMatcher,
    }

    impl Matchers {
        fn new() -> Self {
            Self {
                m_r: R.into(),
                m_r2: R2.into(),
                m_a: A.into(),
                m_a2: A2.into(),
                miss: "yeah, miss".into(),
            }
        }
    }

    #[test]
    fn test_unconditional_match_allow() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Policy::<_, _, ()>::Unconditional(m_r, m_a, Effect::ALLOW);

        let actual = policy.apply(&R, &A);

        assert_eq!(actual, DependentEffect::Fixed(Effect::ALLOW));
    }

    #[test]
    fn test_unconditional_match_deny() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Policy::<_, _, ()>::Unconditional(m_r, m_a, Effect::DENY);

        let actual = policy.apply(&R, &A);

        assert_eq!(actual, DependentEffect::Fixed(Effect::DENY));
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let Matchers { miss, m_a, .. } = Matchers::new();

        let policy = Policy::<_, _, ()>::Unconditional(miss, m_a, Effect::DENY);

        let actual = policy.apply(&R, &A);

        assert_eq!(actual, DependentEffect::Silent);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let Matchers { m_r, miss, .. } = Matchers::new();

        let policy = Policy::<_, _, ()>::Unconditional(m_r, miss, Effect::DENY);

        let actual = policy.apply(&R, &A);

        assert_eq!(actual, DependentEffect::Silent);
    }

    #[test]
    fn test_conditional_matched_allow() {
        let Matchers { m_r, m_a, .. } = Matchers::new();
        let policy = Policy::Conditional(m_r, m_a, Effect::ALLOW, ());

        let actual = policy.apply(&R, &A);

        assert_eq!(actual, DependentEffect::Atomic(Effect::ALLOW, ()));
    }

    #[test]
    fn test_aggregate() {
        let Matchers {
            m_r,
            m_r2,
            m_a,
            m_a2,
            ..
        } = Matchers::new();

        let terms = vec![
            Policy::Conditional(m_r, m_a, Effect::ALLOW, ()),
            Policy::Conditional(m_r2, m_a, Effect::ALLOW, ()),
            Policy::Conditional(m_r, m_a2, Effect::ALLOW, ()),
            Policy::Conditional(m_r2, m_a2, Effect::ALLOW, ()),
            Policy::Unconditional(m_r, m_a, Effect::ALLOW),
            Policy::Unconditional(m_r2, m_a, Effect::ALLOW),
            Policy::Unconditional(m_r, m_a2, Effect::ALLOW),
            Policy::Unconditional(m_r2, m_a2, Effect::ALLOW),
            Policy::Aggregate(vec![
                Policy::Conditional(m_r, m_a, Effect::ALLOW, ()),
                Policy::Conditional(m_r2, m_a, Effect::ALLOW, ()),
                Policy::Conditional(m_r, m_a2, Effect::ALLOW, ()),
                Policy::Conditional(m_r2, m_a2, Effect::ALLOW, ()),
                Policy::Unconditional(m_r, m_a, Effect::ALLOW),
                Policy::Unconditional(m_r2, m_a, Effect::ALLOW),
                Policy::Unconditional(m_r, m_a2, Effect::ALLOW),
                Policy::Unconditional(m_r2, m_a2, Effect::ALLOW),
            ]),
        ];
        let policy = Policy::Aggregate(terms.clone());

        let actual = policy.apply(&R, &A);
        assert_eq!(
            actual,
            DependentEffect::Aggregate(terms.iter().map(|p| p.clone().apply(&R, &A)).collect())
        );
    }

    #[test]
    fn test_disjoint() {
        let Matchers { m_r, m_a, miss, .. } = Matchers::new();

        let policies = vec![
            Policy::Conditional(m_r, m_a, Effect::ALLOW, 18),
            Policy::Conditional(m_r, m_a, Effect::DENY, 19),
            Policy::Unconditional(m_r, m_a, Effect::ALLOW),
            Policy::Unconditional(m_r, m_a, Effect::DENY),
            Policy::Conditional(m_r, miss, Effect::ALLOW, 20),
            Policy::Conditional(miss, m_a, Effect::DENY, 21),
            Policy::Unconditional(miss, m_a, Effect::ALLOW),
            Policy::Unconditional(m_r, miss, Effect::DENY),
            Policy::Aggregate(vec![Policy::Aggregate(vec![
                Policy::Conditional(m_r, m_a, Effect::ALLOW, 18),
                Policy::Conditional(m_r, m_a, Effect::DENY, 19),
                Policy::Unconditional(m_r, m_a, Effect::ALLOW),
                Policy::Unconditional(m_r, m_a, Effect::DENY),
                Policy::Conditional(m_r, miss, Effect::ALLOW, 20),
                Policy::Conditional(miss, m_a, Effect::DENY, 21),
                Policy::Unconditional(miss, m_a, Effect::ALLOW),
                Policy::Unconditional(m_r, miss, Effect::DENY),
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
