//! Policy configurations. A policy is a statement of explicit authorization or denial to
//! perform an action on a resource.

use crate::environment::Environment;

use super::effect::*;
use super::matcher::*;

/// Authorization policy expression.
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy<RMatch, AMatch, CExp> {
    /// Applies if resource and action match but does not depend
    /// on a condition.
    Unconditional(RMatch, AMatch, Effect),

    /// Applies if resource and action match and the condition applies in the
    /// evaluation environment.
    Conditional(RMatch, AMatch, Effect, CExp),

    /// Colledction of policies allowing for recursive composition.
    Complex(Vec<Policy<RMatch, AMatch, CExp>>),
}

impl<R, RMatch, A, AMatch, CExp> Policy<RMatch, AMatch, CExp>
where
    RMatch: Matcher<Target = R>,
    AMatch: Matcher<Target = A>,
{
    /// Determine if policy applies to subject in a specific environment.
    pub fn applies<Env>(&self, resource: &R, action: &A, environment: &Env) -> bool
    where
        Env: Environment<CExp = CExp>,
    {
        use Policy::*;

        match self {
            Complex(_) => true,
            Unconditional(rmatch, amatch, _) => rmatch.test(resource) && amatch.test(action),
            Conditional(rmatch, amatch, _, condition) => {
                rmatch.test(resource) && amatch.test(action) && environment.evaluate(condition)
            }
        }
    }

    /// Determine if policy applies to a resource.
    pub fn applies_to_resource<Env>(&self, resource: &R) -> bool
    where
        Env: Environment<CExp = CExp>,
    {
        use Policy::*;

        match self {
            Complex(_) => true,
            Unconditional(rmatch, amatch, _) => rmatch.test(resource) && amatch.test(action),
            Conditional(rmatch, amatch, _, condition) => {
                rmatch.test(resource) && amatch.test(action) && environment.evaluate(condition)
            }
        }
    }

    /// Determine if policy applies to a resource and action.
    pub fn applies_to_subject(&self, resource: &R, action: &A) -> bool
    where
        Env: Environment<CExp = CExp>,
    {
        use Policy::*;

        match self {
            Complex(_) => true,
            Unconditional(rmatch, amatch, _) => rmatch.test(resource) && amatch.test(action),
            Conditional(rmatch, amatch, _, condition) => {
                rmatch.test(resource) && amatch.test(action) && environment.evaluate(condition)
            }
        }
    }

    // /// Apply policy to a concrete resource and action. Results in a `ComputedEffect` that
    // /// can be evaluated in an environment.
    // pub fn apply(self, resource: &R, action: &A) -> DependentEffect<CExp> {
    //     use Policy::*;

    //     if self.applies(resource, action) {
    //         match self {
    //             Conditional(_, _, eff, cond) => DependentEffect::Conditional(eff, cond),
    //             Unconditional(_, _, eff) => DependentEffect::Unconditional(eff),
    //             Complex(ts) => DependentEffect::Composite(
    //                 ts.into_iter().map(|t| t.apply(resource, action)).collect(),
    //             ),
    //         }
    //     } else {
    //         DependentEffect::Silent
    //     }
    // }

    pub fn apply<Env>(&self, resource: &R, action: &A, environment: &Env) -> ComputedEffect2
    where
        Env: Environment<CExp = CExp>,
    {
        if self.applies(resource, action, environment) {
            use Policy::*;
            match self {
                Conditional(_, _, eff, _) | Unconditional(_, _, eff) => eff.into(),
                Complex(ts) => ComputedEffect2::Complex(
                    ts.iter()
                        .map(|t| t.apply(resource, action, environment))
                        .collect(),
                ),
            }
        } else {
            SILENT2
        }
    }
}

// / Apply multiple policies using a strict algorithm. This is used when evaluating
// / policies for a composite principal (e.g. application + user) where authorization
// / requires all consitutents to be authorized.
// pub fn apply_disjoint<R, A, Iter, CExp, RMatch, AMatch>(
//     policies: Iter,
//     resource: &R,
//     action: &A,
// ) -> DependentEffect<CExp>
// where
//     Iter: IntoIterator<Item = Policy<RMatch, AMatch, CExp>>,
//     RMatch: Matcher<Target = R>,
//     AMatch: Matcher<Target = A>,
// {
//     DependentEffect::Strict(
//         policies
//             .into_iter()
//             .map(|p| p.apply(resource, action))
//             .collect(),
//     )
// }

#[cfg(test)]
mod tests {

    use crate::environment::PositiveEnvironment;

    use super::*;

    type StrMatcher = EqualityMatcher<&'static str>;

    static R: &str = "r";
    static R2: &str = "r2";
    static A: &str = "a";
    static A2: &str = "a2";

    struct TestEnv;

    impl Environment for TestEnv {
        type CExp = bool;

        fn evaluate(&self, exp: &Self::CExp) -> bool {
            *exp
        }
    }

    type TestPolicy = Policy<StrMatcher, StrMatcher, bool>;

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

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, ALLOW2);
    }

    #[test]
    fn test_unconditional_match_deny() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Policy::<_, _, ()>::Unconditional(m_r, m_a, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, DENY2);
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let Matchers { miss, m_a, .. } = Matchers::new();

        let policy = Policy::<_, _, ()>::Unconditional(miss, m_a, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, SILENT2);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let Matchers { m_r, miss, .. } = Matchers::new();

        let policy = Policy::<_, _, ()>::Unconditional(m_r, miss, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, SILENT2);
    }

    #[test]
    fn test_conditional_matched_allow() {
        let Matchers { m_r, m_a, .. } = Matchers::new();
        let policy = Policy::Conditional(m_r, m_a, Effect::ALLOW, ());

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, ALLOW2);
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
            Policy::Complex(vec![
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
        let policy = Policy::Complex(terms.clone());

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());
        assert_eq!(
            actual,
            ComputedEffect2::Complex(
                terms
                    .iter()
                    .map(|p| p.clone().apply(&R, &A, &PositiveEnvironment::default()))
                    .collect()
            )
        );
    }

    #[test]
    fn test_applies_conditional() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Policy::Conditional(m_r, m_a, Effect::ALLOW, true);

        assert!(policy.applies(&R, &A, &TestEnv))
    }

    #[test]
    fn test_applies_unconditional() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Policy::Unconditional(m_r, m_a, Effect::ALLOW);

        assert!(policy.applies(&R, &A, &TestEnv))
    }

    #[test]
    fn test_applies_complex_empty() {
        let Matchers { m_r, m_a, .. } = Matchers::new();
        let env = PositiveEnvironment::<()>::default();

        let policy: TestPolicy = Policy::Complex(Vec::default());

        assert!(!policy.applies(&R, &A, &TestEnv))
    }

    fn test_applies_complex_unmatched() {
        let Matchers { m_r, m_a, .. } = Matchers::new();
        let env = PositiveEnvironment::<()>::default();

        let policy = Policy::Complex(vec![Policy::Conditional(m_r, m_a, Effect::ALLOW, false)]);

        assert!(!policy.applies(&R, &A, &TestEnv))
    }

    fn test_applies_complex_matched() {
        let Matchers { m_r, m_a, .. } = Matchers::new();
        let env = PositiveEnvironment::<()>::default();

        let policy = Policy::Complex(vec![Policy::Conditional(m_r, m_a, Effect::ALLOW, true)]);

        assert!(policy.applies(&R, &A, &TestEnv))
    }

    // #[test]
    // fn test_disjoint() {
    //     let Matchers { m_r, m_a, miss, .. } = Matchers::new();

    //     let policies = vec![
    //         Policy::Conditional(m_r, m_a, Effect::ALLOW, 18),
    //         Policy::Conditional(m_r, m_a, Effect::DENY, 19),
    //         Policy::Unconditional(m_r, m_a, Effect::ALLOW),
    //         Policy::Unconditional(m_r, m_a, Effect::DENY),
    //         Policy::Conditional(m_r, miss, Effect::ALLOW, 20),
    //         Policy::Conditional(miss, m_a, Effect::DENY, 21),
    //         Policy::Unconditional(miss, m_a, Effect::ALLOW),
    //         Policy::Unconditional(m_r, miss, Effect::DENY),
    //         Policy::Complex(vec![Policy::Complex(vec![
    //             Policy::Conditional(m_r, m_a, Effect::ALLOW, 18),
    //             Policy::Conditional(m_r, m_a, Effect::DENY, 19),
    //             Policy::Unconditional(m_r, m_a, Effect::ALLOW),
    //             Policy::Unconditional(m_r, m_a, Effect::DENY),
    //             Policy::Conditional(m_r, miss, Effect::ALLOW, 20),
    //             Policy::Conditional(miss, m_a, Effect::DENY, 21),
    //             Policy::Unconditional(miss, m_a, Effect::ALLOW),
    //             Policy::Unconditional(m_r, miss, Effect::DENY),
    //         ])]),
    //     ];
    //     let r = "r";
    //     let a = "a";

    //     let actual = apply_disjoint(policies.clone(), &r, &a);

    //     let expected = DependentEffect::Strict(
    //         policies
    //             .iter()
    //             .map(|p| p.clone().apply(&"r", &"a"))
    //             .collect(),
    //     );
    //     assert_eq!(actual, expected);
    // }
}
