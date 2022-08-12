//! Policy configuration and evaluation. A policy states the authorization configuration for a
//! principal. A policy can be evaluated against three kinds of conditions:
//! 1. Resource: a policy applies to specified subject resoureces
//! 1. Action: a policy applies to specified subject actions
//! 1. Environment: a policy applies under specified environmental conditions
//!
//! A policy is modeled as a set of [primitive rules](Assertion), each of which selects
//! the [definite effect](Effect) of matching some conditions.
//!

use crate::environment::Environment;

use super::effect::*;
use super::matcher::*;

/// Authorization policy assertion.
///
#[derive(Clone, Debug, PartialEq, Eq)]
/// Authorization poliicy primitve rule. Describes an effect of meeting
/// resource, action, and environmental conditions.
pub enum Assertion<RMatch, AMatch, CExp> {
    /// Rule that matches under any environmental condition. Available to simplify
    /// expression for systems  that do not use environmental evaluation.
    Unconditional(RMatch, AMatch, Effect),

    /// Rule that matches resource, action, and environmental conditions.
    Conditional(RMatch, AMatch, Effect, CExp),
}

impl<RMatch, AMatch, CExp> Assertion<RMatch, AMatch, CExp> {
    /// Create an asserion that all access is denied.
    pub fn deny_all() -> Self
    where
        RMatch: ExtendedMatcher,
        AMatch: ExtendedMatcher,
    {
        Assertion::Unconditional(RMatch::match_any(), AMatch::match_any(), Effect::DENY)
    }

    /// Create an asserion that any access is allowed.
    pub fn allow_any() -> Self
    where
        RMatch: ExtendedMatcher,
        AMatch: ExtendedMatcher,
    {
        Assertion::Unconditional(RMatch::match_any(), AMatch::match_any(), Effect::ALLOW)
    }

    pub fn for_subject(&self) -> SubjectAssertion<CExp> {
        todo!();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Policy<As>(Vec<As>);

impl<RMatch, AMatch, CExp> Policy<Assertion<RMatch, AMatch, CExp>> {
    pub fn iter(&self) -> impl Iterator<Item = &Assertion<RMatch, AMatch, CExp>> {
        self.0.iter()
    }

    /// Create a policy that denies all access.
    pub fn deny_all() -> Self
    where
        RMatch: ExtendedMatcher,
        AMatch: ExtendedMatcher,
    {
        Assertion::deny_all().into()
    }

    /// Create a policy that allows any access.
    pub fn allow_any() -> Self
    where
        RMatch: ExtendedMatcher,
        AMatch: ExtendedMatcher,
    {
        Assertion::allow_any().into()
    }

    /// Supply an iterator over assertions that match the provided subject (resource and action).
    /// Matched policies are converted to SubjectPolicy's. The iterator supplies its results
    /// in arbitrary order.
    pub fn for_subject<'a, R, A>(
        &self,
        resource: &'a R,
        action: &'a A,
    ) -> ForSubjectIter<'a, std::slice::Iter<Assertion<RMatch, AMatch, CExp>>, R, A>
    where
        RMatch: Matcher<Target = R>,
        AMatch: Matcher<Target = A>,
    {
        ForSubjectIter {
            resource,
            action,
            source: self.0.iter(),
        }
    }
}

impl<RMatch, AMatch, CExp> FromIterator<Assertion<RMatch, AMatch, CExp>>
    for Policy<Assertion<RMatch, AMatch, CExp>>
{
    fn from_iter<T: IntoIterator<Item = Assertion<RMatch, AMatch, CExp>>>(items: T) -> Self {
        Policy(items.into_iter().collect())
    }
}

impl<RMatch, AMatch, CExp> From<Vec<Assertion<RMatch, AMatch, CExp>>>
    for Policy<Assertion<RMatch, AMatch, CExp>>
{
    fn from(items: Vec<Assertion<RMatch, AMatch, CExp>>) -> Self {
        Policy(items)
    }
}

impl<RMatch, AMatch, CExp> From<Assertion<RMatch, AMatch, CExp>>
    for Policy<Assertion<RMatch, AMatch, CExp>>
{
    fn from(item: Assertion<RMatch, AMatch, CExp>) -> Self {
        vec![item].into()
    }
}

impl<RMatch, AMatch, CExp> IntoIterator for Policy<Assertion<RMatch, AMatch, CExp>> {
    type Item = Assertion<RMatch, AMatch, CExp>;

    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<R, RMatch, A, AMatch, CExp> Assertion<RMatch, AMatch, CExp>
where
    RMatch: Matcher<Target = R>,
    AMatch: Matcher<Target = A>,
{
    /// Determine if specification applies to subject in a specific environment.
    pub fn applies<Env>(&self, resource: &R, action: &A, environment: &Env) -> bool
    where
        Env: Environment<CExp = CExp>,
    {
        use Assertion::*;

        match self {
            // Compound(ps) => ps
            //     .iter()
            //     .map(|p| p.applies(resource, action, environment))
            //     .any(|p| p),
            Unconditional(rmatch, amatch, _) => rmatch.test(resource) && amatch.test(action),
            Conditional(rmatch, amatch, _, condition) => {
                rmatch.test(resource) && amatch.test(action) && environment.evaluate(condition)
            }
        }
    }

    /// Determine if specification applies to a resource.
    pub fn applies_to_resource(&self, resource: &R) -> bool {
        use Assertion::*;

        match self {
            Unconditional(rmatch, _, _) => rmatch.test(resource),
            Conditional(rmatch, _, _, _) => rmatch.test(resource),
        }
    }

    /// Determine if specification applies to a resource and action.
    pub fn applies_to_action(&self, action: &A) -> bool {
        use Assertion::*;

        match self {
            // Compound(ps) => ps.iter().any(|p| p.applies_to_action(action)),
            Unconditional(_, amatch, _) => amatch.test(action),
            Conditional(_, amatch, _, _) => amatch.test(action),
        }
    }

    /// Determine if specification applies to a resource and action.
    pub fn applies_to_subject(&self, resource: &R, action: &A) -> bool {
        use Assertion::*;

        match self {
            Unconditional(rmatch, amatch, _) => rmatch.test(resource) && amatch.test(action),
            Conditional(rmatch, amatch, _, _) => rmatch.test(resource) && amatch.test(action),
        }
    }

    pub fn apply<Env>(&self, resource: &R, action: &A, environment: &Env) -> ComputedEffect
    where
        Env: Environment<CExp = CExp>,
    {
        if self.applies(resource, action, environment) {
            use Assertion::*;
            match self {
                Conditional(_, _, eff, _) | Unconditional(_, _, eff) => eff.into(),
            }
        } else {
            SILENT
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum SubjectAssertion<CExp> {
    Unconditional(Effect),
    Conditional(Effect, CExp),
}

pub struct ForSubjectIter<'parm, Src, R, A> {
    resource: &'parm R,
    action: &'parm A,
    source: Src,
}

impl<'param, RMatch, R, AMatch, A, CExp, Src> Iterator for ForSubjectIter<'param, Src, R, A>
where
    Src: Iterator<Item = &'param Assertion<RMatch, AMatch, CExp>> + 'param,
    RMatch: Matcher<Target = R> + 'param + std::fmt::Debug,
    AMatch: Matcher<Target = A> + 'param + std::fmt::Debug,
    CExp: Clone + 'param + std::fmt::Debug,
{
    type Item = SubjectAssertion<CExp>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(snext) = self.source.next() {
            if snext.applies_to_subject(self.resource, self.action) {
                match snext {
                    Assertion::Conditional(_, _, eff, exp) => {
                        return Some(SubjectAssertion::Conditional(*eff, exp.clone()))
                    }
                    Assertion::Unconditional(_, _, eff) => {
                        return Some(SubjectAssertion::Unconditional(*eff))
                    } // Assertion::Compound(_) => {
                      //     panic!("Compound assertion is going away");
                      // }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use crate::environment::{PositiveEnvironment, TrivialEnv};

    use super::*;

    type StrMatcher = EqualityMatcher<&'static str>;

    static R: &str = "r";
    static R2: &str = "r2";
    static A: &str = "a";
    static A2: &str = "a2";

    type TestAssertion = Assertion<StrMatcher, StrMatcher, bool>;
    type TestPolicy = Policy<TestAssertion>;

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

        let policy = Assertion::<_, _, ()>::Unconditional(m_r, m_a, Effect::ALLOW);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, ALLOW);
    }

    #[test]
    fn test_unconditional_match_deny() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Assertion::<_, _, ()>::Unconditional(m_r, m_a, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, DENY);
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let Matchers { miss, m_a, .. } = Matchers::new();

        let policy = Assertion::<_, _, ()>::Unconditional(miss, m_a, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, SILENT);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let Matchers { m_r, miss, .. } = Matchers::new();

        let policy = Assertion::<_, _, ()>::Unconditional(m_r, miss, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, SILENT);
    }

    #[test]
    fn test_conditional_matched_allow() {
        let Matchers { m_r, m_a, .. } = Matchers::new();
        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, ());

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, ALLOW);
    }

    #[test]
    fn test_assertion_deny_all() {
        let actual: TestAssertion = Assertion::deny_all();
        let expected: TestAssertion = Assertion::Unconditional(
            StrMatcher::match_any(),
            StrMatcher::match_any(),
            Effect::DENY,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_assertion_allow_any() {
        let actual: TestAssertion = Assertion::allow_any();
        let expected: TestAssertion = Assertion::Unconditional(
            StrMatcher::match_any(),
            StrMatcher::match_any(),
            Effect::ALLOW,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_policy_deny_all() {
        let actual: TestPolicy = Policy::deny_all();
        let expected: TestPolicy = TestAssertion::deny_all().into();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_policy_allow_any() {
        let actual: TestPolicy = Policy::allow_any();
        let expected: TestPolicy = TestAssertion::allow_any().into();

        assert_eq!(actual, expected);
    }

    // #[test]
    // fn test_aggregate() {
    //     let Matchers {
    //         m_r,
    //         m_r2,
    //         m_a,
    //         m_a2,
    //         ..
    //     } = Matchers::new();

    //     let terms = vec![
    //         Assertion::Conditional(m_r, m_a, Effect::ALLOW, ()),
    //         Assertion::Conditional(m_r2, m_a, Effect::ALLOW, ()),
    //         Assertion::Conditional(m_r, m_a2, Effect::ALLOW, ()),
    //         Assertion::Conditional(m_r2, m_a2, Effect::ALLOW, ()),
    //         Assertion::Unconditional(m_r, m_a, Effect::ALLOW),
    //         Assertion::Unconditional(m_r2, m_a, Effect::ALLOW),
    //         Assertion::Unconditional(m_r, m_a2, Effect::ALLOW),
    //         Assertion::Unconditional(m_r2, m_a2, Effect::ALLOW),
    //         Assertion::Conditional(m_r, m_a, Effect::ALLOW, ()),
    //         Assertion::Conditional(m_r2, m_a, Effect::ALLOW, ()),
    //         Assertion::Conditional(m_r, m_a2, Effect::ALLOW, ()),
    //         Assertion::Conditional(m_r2, m_a2, Effect::ALLOW, ()),
    //         Assertion::Unconditional(m_r, m_a, Effect::ALLOW),
    //         Assertion::Unconditional(m_r2, m_a, Effect::ALLOW),
    //         Assertion::Unconditional(m_r, m_a2, Effect::ALLOW),
    //         Assertion::Unconditional(m_r2, m_a2, Effect::ALLOW),
    //     ];
    //     let policy: OldTestPolicy = terms.into_iter().collect();

    //     todo!();
    //     // let actual = policy.apply(&R, &A, &PositiveEnvironment::default());
    //     // assert_eq!(
    //     //     actual,
    //     //     ComputedEffect2::Complex(
    //     //         terms
    //     //             .iter()
    //     //             .map(|p| p.clone().apply(&R, &A, &PositiveEnvironment::default()))
    //     //             .collect()
    //     //     )
    //     // );
    // }

    #[test]
    fn test_applies_conditional() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, true);

        assert!(policy.applies(&R, &A, &TrivialEnv));
    }

    #[test]
    fn test_applies_unconditional() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Assertion::Unconditional(m_r, m_a, Effect::ALLOW);

        assert!(policy.applies(&R, &A, &TrivialEnv));
    }

    // #[test]
    // fn test_applies_complex_empty() {
    //     let policy: TestAssertion = Assertion::Compound(Vec::default());

    //     assert!(!policy.applies(&R, &A, &TrivialEnv));
    // }

    // #[test]
    // fn test_applies_complex_unmatched() {
    //     let Matchers { m_r, m_a, .. } = Matchers::new();

    //     let policy =
    //         Assertion::Compound(vec![Assertion::Conditional(m_r, m_a, Effect::ALLOW, false)]);

    //     assert!(!policy.applies(&R, &A, &TrivialEnv));
    // }

    // #[test]
    // fn test_applies_complex_matched() {
    //     let Matchers { m_r, m_a, .. } = Matchers::new();

    //     let policy: TestPolicy = [
    //         Assertion::Conditional(m_r, m_a, Effect::ALLOW, false),
    //         Assertion::Conditional(m_r, m_a, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r, m_a, Effect::ALLOW, false),
    //     ]
    //     .into_iter()
    //     .collect();

    //     assert!(policy.applies(&R, &A, &TrivialEnv));
    // }

    #[test]
    fn test_applies_to_subject_conditional() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, false);
        assert!(policy.applies_to_subject(&R, &A));
        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, true);
        assert!(policy.applies_to_subject(&R, &A));
    }

    #[test]
    fn test_applies_to_subject_unconditional() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy: TestAssertion = Assertion::Unconditional(m_r, m_a, Effect::ALLOW);

        assert!(policy.applies_to_subject(&R, &A,));
    }

    // #[test]
    // fn test_applies_to_subject_complex_empty() {
    //     let policy: TestAssertion = Assertion::Compound(Vec::default());

    //     assert!(!policy.applies_to_subject(&R, &A));
    // }

    // #[test]
    // fn test_applies_to_subject_complex_unmatched() {
    //     let Matchers {
    //         m_r2,
    //         m_r,
    //         m_a2,
    //         m_a,
    //         ..
    //     } = Matchers::new();

    //     let policy = Assertion::Compound(vec![
    //         Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
    //     ]);

    //     assert!(!policy.applies_to_subject(&R, &A));
    // }

    // #[test]
    // fn test_applies_to_subject_complex_matched() {
    //     let Matchers {
    //         m_r2,
    //         m_r,
    //         m_a2,
    //         m_a,
    //         ..
    //     } = Matchers::new();

    //     let policy = Assertion::Compound(vec![
    //         Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r, m_a, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
    //     ]);

    //     assert!(policy.applies_to_subject(&R, &A));
    // }

    #[test]
    fn test_applies_to_resource_conditional() {
        let Matchers { m_r, m_a, m_a2, .. } = Matchers::new();

        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, true);
        assert!(policy.applies_to_resource(&R));
        let policy = Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true);
        assert!(policy.applies_to_resource(&R));
    }

    #[test]
    fn test_applies_to_resource_unconditional() {
        let Matchers { m_r, m_a, m_a2, .. } = Matchers::new();

        let policy: TestAssertion = Assertion::Unconditional(m_r, m_a, Effect::ALLOW);
        assert!(policy.applies_to_resource(&R));
        let policy: TestAssertion = Assertion::Unconditional(m_r, m_a2, Effect::ALLOW);
        assert!(policy.applies_to_resource(&R));
    }

    // #[test]
    // fn test_applies_to_resource_complex_empty() {
    //     let policy: TestAssertion = Assertion::Compound(Vec::default());

    //     assert!(!policy.applies_to_resource(&R));
    // }

    // #[test]
    // fn test_applies_to_resource_complex_unmatched() {
    //     let Matchers { m_r2, m_a, .. } = Matchers::new();

    //     let policy = Assertion::Compound(vec![
    //         Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
    //     ]);

    //     assert!(!policy.applies_to_resource(&R));
    // }

    // #[test]
    // fn test_applies_to_resource_complex_matched() {
    //     let Matchers { m_r2, m_r, m_a, .. } = Matchers::new();

    //     let policy = Assertion::Compound(vec![
    //         Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r, m_a, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
    //     ]);

    //     assert!(policy.applies_to_resource(&R));
    // }

    #[test]
    fn test_applies_to_action_conditional() {
        let Matchers { m_r, m_r2, m_a, .. } = Matchers::new();

        let policy = Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true);
        assert!(policy.applies_to_action(&A));
        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, true);
        assert!(policy.applies_to_action(&A));
    }

    #[test]
    fn test_applies_to_action_unconditional() {
        let Matchers { m_r, m_r2, m_a, .. } = Matchers::new();

        let policy: TestAssertion = Assertion::Unconditional(m_r, m_a, Effect::ALLOW);
        assert!(policy.applies_to_action(&A));
        let policy: TestAssertion = Assertion::Unconditional(m_r2, m_a, Effect::ALLOW);
        assert!(policy.applies_to_action(&A));
    }

    // #[test]
    // fn test_applies_to_action_complex_empty() {
    //     let policy: TestAssertion = Assertion::Compound(Vec::default());

    //     assert!(!policy.applies_to_action(&A));
    // }

    // #[test]
    // fn test_applies_to_action_complex_unmatched() {
    //     let Matchers { m_r, m_a2, .. } = Matchers::new();

    //     let policy = Assertion::Compound(vec![
    //         Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
    //     ]);

    //     assert!(!policy.applies_to_action(&A));
    // }

    // #[test]
    // fn test_applies_to_action_complex_matched() {
    //     let Matchers { m_r, m_a, m_a2, .. } = Matchers::new();

    //     let policy = Assertion::Compound(vec![
    //         Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r, m_a, Effect::ALLOW, true),
    //         Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
    //     ]);

    //     assert!(policy.applies_to_action(&A));
    // }

    #[test]
    fn test_policy_iteration_and_collection() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let terms = vec![
            Assertion::Unconditional(m_r, m_a, Effect::ALLOW),
            Assertion::Unconditional(m_r, m_a, Effect::DENY),
            Assertion::Conditional(m_r, m_a, Effect::DENY, true),
            Assertion::Unconditional(m_r, m_a, Effect::ALLOW),
            Assertion::Unconditional(m_r, m_a, Effect::ALLOW),
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, false),
        ];

        let policy: TestPolicy = terms.iter().cloned().collect();

        assert_eq!(policy.iter().cloned().collect::<Vec<_>>(), terms);
        assert_eq!(policy.into_iter().collect::<Vec<_>>(), terms);

        let actual = terms
            .iter()
            .cloned()
            .collect::<TestPolicy>()
            .into_iter()
            .collect::<Vec<_>>();

        assert_eq!(actual, terms);
    }

    #[test]
    fn test_for_subject() {
        let Matchers { m_r, m_r2, m_a, .. } = Matchers::new();

        let policy: TestPolicy = [Assertion::Conditional(m_r, m_a, Effect::ALLOW, false)]
            .into_iter()
            .collect();
        let spolicy: Vec<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(
            spolicy,
            vec![SubjectAssertion::Conditional(Effect::ALLOW, false)]
        );

        let policy: TestPolicy = [Assertion::Unconditional(m_r, m_a, Effect::DENY)]
            .into_iter()
            .collect();
        let spolicy: Vec<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(spolicy, vec![SubjectAssertion::Unconditional(Effect::DENY)]);

        let policy: TestPolicy = [].into_iter().collect();
        let spolicy: Vec<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(spolicy, vec![]);

        let policy: TestPolicy = [Assertion::Unconditional(m_r2, m_a, Effect::ALLOW)]
            .into_iter()
            .collect();
        let spolicy: Vec<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(spolicy, vec![]);

        let policy: TestPolicy = [
            Assertion::Unconditional(m_r, m_a, Effect::ALLOW), // matches
            Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, false), // matches
            Assertion::Conditional(m_r, m_a, Effect::DENY, true),   // matches
            Assertion::Unconditional(m_r2, m_a, Effect::ALLOW),
        ]
        .into_iter()
        .collect();
        let spolicy: HashSet<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(
            spolicy,
            [
                SubjectAssertion::Unconditional(Effect::ALLOW),
                SubjectAssertion::Conditional(Effect::ALLOW, false),
                SubjectAssertion::Conditional(Effect::DENY, true)
            ]
            .into_iter()
            .collect()
        );
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
