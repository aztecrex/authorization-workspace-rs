//! Policy configurations.

use super::dependent_effect::*;
use super::effect::*;

/// Trait for matching resources. When evaluating a policy, this is used to determine if
/// the policy applies with respect to a concrete resource.
pub trait ResourceMatch {
    /// The type of resource that can be matched.
    type Resource;

    /// Determine if a concrete resource matches
    fn test(&self, resource: &Self::Resource) -> bool;
}

/// Trait for matching actions. When evaluating a policy, this is used to determine if
/// the policy applies with respect to a concrete action.
pub trait ActionMatch {
    /// The type of action matched by this implementation.
    type Action;

    /// Determine if a concrete action matches
    fn test(&self, action: &Self::Action) -> bool;
}

/// Trivial str resource
pub struct StrResource<'a>(&'a str);

/// Trivial str action
pub struct StrAction<'a>(&'a str);

/// Trivial str matcher
pub struct StrMatcher<'a>(&'a str);

impl<'a> ResourceMatch for StrMatcher<'a> {
    type Resource = StrResource<'a>;
    fn test(&self, resource: &Self::Resource) -> bool {
        self.0 == resource.0
    }
}

impl<'a> ActionMatch for StrMatcher<'a> {
    type Action = StrAction<'a>;
    fn test(&self, action: &Self::Action) -> bool {
        self.0 == action.0
    }
}

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
    RMatch: ResourceMatch<Resource = R>,
    AMatch: ActionMatch<Action = A>,
{
    /// Determine if policy applies to a concrete resource and action.
    ///
    pub fn applies(&self, resource: &R, action: &A) -> bool {
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
    RMatch: ResourceMatch<Resource = R>,
    AMatch: ActionMatch<Action = A>,
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
    fn test_str_matcher_resource() {
        let matcher = StrMatcher("abc");
        assert_eq!(
            <StrMatcher as ResourceMatch>::test(&matcher, &StrResource("abc")),
            true
        );
        assert_eq!(
            <StrMatcher as ResourceMatch>::test(&matcher, &StrResource("xyz")),
            false
        );
    }

    #[test]
    fn test_str_matcher_action() {
        let matcher = StrMatcher("abc");
        assert_eq!(
            <StrMatcher as ActionMatch>::test(&matcher, &StrAction("abc")),
            true
        );
        assert_eq!(
            <StrMatcher as ActionMatch>::test(&matcher, &StrAction("xyz")),
            false
        );
    }

    #[test]
    fn test_unconditional_match_allow() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_A, Effect::ALLOW);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, DependentEffect::Fixed(Effect::ALLOW));
    }

    #[test]
    fn test_unconditional_match_deny() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_A, Effect::DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, DependentEffect::Fixed(Effect::DENY));
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_MISS, MATCH_A, Effect::DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, DependentEffect::Silent);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let policy = Policy::<_, _, ()>::Unconditional(MATCH_R, MATCH_MISS, Effect::DENY);

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, DependentEffect::Silent);
    }

    #[test]
    fn test_conditional_matched_allow() {
        let policy = Policy::Conditional(MATCH_R, MATCH_A, Effect::ALLOW, ());

        let actual = policy.apply(&Resource("r"), &Action("a"));

        assert_eq!(actual, DependentEffect::Atomic(Effect::ALLOW, ()));
    }

    #[test]
    fn test_aggregate() {
        let match_r1 = Matcher("r1");
        let match_r2 = Matcher("r2");
        let match_a1 = Matcher("a1");
        let match_a2 = Matcher("a2");
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

        let actual = policy.apply(&Resource("r1"), &Action("a1"));
        assert_eq!(
            actual,
            DependentEffect::Aggregate(
                terms
                    .iter()
                    .map(|p| p.clone().apply(&Resource("r1"), &Action("a1")))
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
            Policy::Conditional(MATCH_MISS, MATCH_A, Effect::DENY, 21),
            Policy::Unconditional(MATCH_MISS, MATCH_A, Effect::ALLOW),
            Policy::Unconditional(MATCH_R, MATCH_MISS, Effect::DENY),
            Policy::Aggregate(vec![Policy::Aggregate(vec![
                Policy::Conditional(MATCH_R, MATCH_A, Effect::ALLOW, 18),
                Policy::Conditional(MATCH_R, MATCH_A, Effect::DENY, 19),
                Policy::Unconditional(MATCH_R, MATCH_A, Effect::ALLOW),
                Policy::Unconditional(MATCH_R, MATCH_A, Effect::DENY),
                Policy::Conditional(MATCH_R, MATCH_MISS, Effect::ALLOW, 20),
                Policy::Conditional(MATCH_MISS, MATCH_A, Effect::DENY, 21),
                Policy::Unconditional(MATCH_MISS, MATCH_A, Effect::ALLOW),
                Policy::Unconditional(MATCH_R, MATCH_MISS, Effect::DENY),
            ])]),
        ];
        let r = Resource("r");
        let a = Action("a");

        let actual = apply_disjoint(policies.clone(), &r, &a);

        let expected = DependentEffect::Disjoint(
            policies
                .iter()
                .map(|p| p.clone().apply(&Resource("r"), &Action("a")))
                .collect(),
        );
        assert_eq!(actual, expected);
    }
}
