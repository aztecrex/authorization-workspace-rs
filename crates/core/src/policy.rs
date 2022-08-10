//! Policy configurations. A policy is a statement of explicit authorization or denial to
//! perform an action on a resource.

use std::collections::VecDeque;

use crate::environment::Environment;

use super::effect::*;
use super::matcher::*;

/// Authorization policy assertion.
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Assertion<RMatch, AMatch, CExp> {
    /// Applies if resource and action match but does not depend
    /// on a condition.
    Unconditional(RMatch, AMatch, Effect),

    /// Applies if resource and action match and the condition applies in the
    /// evaluation environment.
    Conditional(RMatch, AMatch, Effect, CExp),
    /// Colledction of policies allowing for recursive composition. Although
    /// the collection is implemented as a Vec, order is not important. Policy
    /// processing is free to re-order the results.
    Compound(Vec<Self>),
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Policy<RMatch, AMatch, CExp>(Vec<Assertion<RMatch, AMatch, CExp>>);

impl<RMatch, AMatch, CExp> Policy<RMatch, AMatch, CExp> {
    pub fn iter(&self) -> impl Iterator<Item = &Assertion<RMatch, AMatch, CExp>> {
        self.0.iter()
    }
}

impl<RMatch, AMatch, CExp> FromIterator<Assertion<RMatch, AMatch, CExp>>
    for Policy<RMatch, AMatch, CExp>
{
    fn from_iter<T: IntoIterator<Item = Assertion<RMatch, AMatch, CExp>>>(items: T) -> Self {
        Policy(items.into_iter().collect())
    }
}

impl<RMatch, AMatch, CExp> From<Vec<Assertion<RMatch, AMatch, CExp>>>
    for Policy<RMatch, AMatch, CExp>
{
    fn from(items: Vec<Assertion<RMatch, AMatch, CExp>>) -> Self {
        Policy(items)
    }
}

impl<RMatch, AMatch, CExp> IntoIterator for Policy<RMatch, AMatch, CExp> {
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
    /// Determine if policy applies to subject in a specific environment.
    pub fn applies<Env>(&self, resource: &R, action: &A, environment: &Env) -> bool
    where
        Env: Environment<CExp = CExp>,
    {
        use Assertion::*;

        match self {
            Compound(ps) => ps
                .iter()
                .map(|p| p.applies(resource, action, environment))
                .any(|p| p),
            Unconditional(rmatch, amatch, _) => rmatch.test(resource) && amatch.test(action),
            Conditional(rmatch, amatch, _, condition) => {
                rmatch.test(resource) && amatch.test(action) && environment.evaluate(condition)
            }
        }
    }

    /// Determine if policy applies to a resource.
    pub fn applies_to_resource(&self, resource: &R) -> bool {
        use Assertion::*;

        match self {
            Compound(ps) => ps
                .iter()
                .map(|p| p.applies_to_resource(resource))
                .any(|p| p),
            Unconditional(rmatch, _, _) => rmatch.test(resource),
            Conditional(rmatch, _, _, _) => rmatch.test(resource),
        }
    }

    /// Determine if policy applies to a resource and action.
    pub fn applies_to_action(&self, action: &A) -> bool {
        use Assertion::*;

        match self {
            Compound(ps) => ps.iter().any(|p| p.applies_to_action(action)),
            Unconditional(_, amatch, _) => amatch.test(action),
            Conditional(_, amatch, _, _) => amatch.test(action),
        }
    }

    /// Determine if policy applies to a resource and action.
    pub fn applies_to_subject(&self, resource: &R, action: &A) -> bool {
        use Assertion::*;

        match self {
            Compound(ps) => ps.iter().any(|p| p.applies_to_subject(resource, action)),
            Unconditional(rmatch, amatch, _) => rmatch.test(resource) && amatch.test(action),
            Conditional(rmatch, amatch, _, _) => rmatch.test(resource) && amatch.test(action),
        }
    }

    pub fn apply<Env>(&self, resource: &R, action: &A, environment: &Env) -> ComputedEffect2
    where
        Env: Environment<CExp = CExp>,
    {
        if self.applies(resource, action, environment) {
            use Assertion::*;
            match self {
                Conditional(_, _, eff, _) | Unconditional(_, _, eff) => eff.into(),
                Compound(ts) => ComputedEffect2::Complex(
                    ts.iter()
                        .map(|t| t.apply(resource, action, environment))
                        .collect(),
                ),
            }
        } else {
            SILENT2
        }
    }

    /// Supply an iterator over policies that match the provided subject (resource and action).
    /// Matched policies are converted to SubjectPolicy's. The iterator supplies its results
    /// in arbitrary order.
    pub fn for_subject<'a>(
        &self,
        resource: &'a R,
        action: &'a A,
    ) -> ForSubjectIterator<'a, Self, <[&Self; 1] as IntoIterator>::IntoIter, R, A> {
        ForSubjectIterator {
            resource,
            action,
            source: [self].into_iter(),
            queue: VecDeque::default(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum SubjectPolicy<CExp> {
    Unconditional(Effect),
    Conditional(Effect, CExp),
}

pub struct ForSubjectIterator<'parm, Pol, Src, R, A> {
    resource: &'parm R,
    action: &'parm A,
    source: Src,
    queue: VecDeque<&'parm Pol>,
}

impl<'param, RMatch, R, AMatch, A, CExp, Src> Iterator
    for ForSubjectIterator<'param, Assertion<RMatch, AMatch, CExp>, Src, R, A>
where
    Src: Iterator<Item = &'param Assertion<RMatch, AMatch, CExp>> + 'param,
    RMatch: Matcher<Target = R> + 'param + std::fmt::Debug,
    AMatch: Matcher<Target = A> + 'param + std::fmt::Debug,
    CExp: Clone + 'param + std::fmt::Debug,
{
    type Item = SubjectPolicy<CExp>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            eprintln!("queue: {:?}", self.queue);
            if let Some(qpol) = self.queue.pop_front() {
                if qpol.applies_to_subject(self.resource, self.action) {
                    match qpol {
                        Assertion::Conditional(_, _, eff, exp) => {
                            return Some(SubjectPolicy::Conditional(*eff, exp.clone()))
                        }
                        Assertion::Unconditional(_, _, eff) => {
                            return Some(SubjectPolicy::Unconditional(*eff))
                        }
                        Assertion::Compound(ts) => {
                            self.queue.extend(ts.iter());
                        }
                    }
                }
            } else if let Some(spol) = self.source.next() {
                self.queue.push_back(spol);
            } else {
                return None;
            }
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

    use std::collections::HashSet;

    use crate::environment::{PositiveEnvironment, TrivialEnv};

    use super::*;

    type StrMatcher = EqualityMatcher<&'static str>;

    static R: &str = "r";
    static R2: &str = "r2";
    static A: &str = "a";
    static A2: &str = "a2";

    type TestPolicy = Assertion<StrMatcher, StrMatcher, bool>;

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

        assert_eq!(actual, ALLOW2);
    }

    #[test]
    fn test_unconditional_match_deny() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Assertion::<_, _, ()>::Unconditional(m_r, m_a, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, DENY2);
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let Matchers { miss, m_a, .. } = Matchers::new();

        let policy = Assertion::<_, _, ()>::Unconditional(miss, m_a, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, SILENT2);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let Matchers { m_r, miss, .. } = Matchers::new();

        let policy = Assertion::<_, _, ()>::Unconditional(m_r, miss, Effect::DENY);

        let actual = policy.apply(&R, &A, &PositiveEnvironment::default());

        assert_eq!(actual, SILENT2);
    }

    #[test]
    fn test_conditional_matched_allow() {
        let Matchers { m_r, m_a, .. } = Matchers::new();
        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, ());

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
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, ()),
            Assertion::Conditional(m_r2, m_a, Effect::ALLOW, ()),
            Assertion::Conditional(m_r, m_a2, Effect::ALLOW, ()),
            Assertion::Conditional(m_r2, m_a2, Effect::ALLOW, ()),
            Assertion::Unconditional(m_r, m_a, Effect::ALLOW),
            Assertion::Unconditional(m_r2, m_a, Effect::ALLOW),
            Assertion::Unconditional(m_r, m_a2, Effect::ALLOW),
            Assertion::Unconditional(m_r2, m_a2, Effect::ALLOW),
            Assertion::Compound(vec![
                Assertion::Conditional(m_r, m_a, Effect::ALLOW, ()),
                Assertion::Conditional(m_r2, m_a, Effect::ALLOW, ()),
                Assertion::Conditional(m_r, m_a2, Effect::ALLOW, ()),
                Assertion::Conditional(m_r2, m_a2, Effect::ALLOW, ()),
                Assertion::Unconditional(m_r, m_a, Effect::ALLOW),
                Assertion::Unconditional(m_r2, m_a, Effect::ALLOW),
                Assertion::Unconditional(m_r, m_a2, Effect::ALLOW),
                Assertion::Unconditional(m_r2, m_a2, Effect::ALLOW),
            ]),
        ];
        let policy = Assertion::Compound(terms.clone());

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

        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, true);

        assert!(policy.applies(&R, &A, &TrivialEnv));
    }

    #[test]
    fn test_applies_unconditional() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Assertion::Unconditional(m_r, m_a, Effect::ALLOW);

        assert!(policy.applies(&R, &A, &TrivialEnv));
    }

    #[test]
    fn test_applies_complex_empty() {
        let policy: TestPolicy = Assertion::Compound(Vec::default());

        assert!(!policy.applies(&R, &A, &TrivialEnv));
    }

    #[test]
    fn test_applies_complex_unmatched() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy =
            Assertion::Compound(vec![Assertion::Conditional(m_r, m_a, Effect::ALLOW, false)]);

        assert!(!policy.applies(&R, &A, &TrivialEnv));
    }

    #[test]
    fn test_applies_complex_matched() {
        let Matchers { m_r, m_a, .. } = Matchers::new();

        let policy = Assertion::Compound(vec![
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, false),
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, false),
        ]);

        assert!(policy.applies(&R, &A, &TrivialEnv));
    }

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

        let policy: TestPolicy = Assertion::Unconditional(m_r, m_a, Effect::ALLOW);

        assert!(policy.applies_to_subject(&R, &A,));
    }

    #[test]
    fn test_applies_to_subject_complex_empty() {
        let policy: TestPolicy = Assertion::Compound(Vec::default());

        assert!(!policy.applies_to_subject(&R, &A));
    }

    #[test]
    fn test_applies_to_subject_complex_unmatched() {
        let Matchers {
            m_r2,
            m_r,
            m_a2,
            m_a,
            ..
        } = Matchers::new();

        let policy = Assertion::Compound(vec![
            Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
        ]);

        assert!(!policy.applies_to_subject(&R, &A));
    }

    #[test]
    fn test_applies_to_subject_complex_matched() {
        let Matchers {
            m_r2,
            m_r,
            m_a2,
            m_a,
            ..
        } = Matchers::new();

        let policy = Assertion::Compound(vec![
            Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
        ]);

        assert!(policy.applies_to_subject(&R, &A));
    }

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

        let policy: TestPolicy = Assertion::Unconditional(m_r, m_a, Effect::ALLOW);
        assert!(policy.applies_to_resource(&R));
        let policy: TestPolicy = Assertion::Unconditional(m_r, m_a2, Effect::ALLOW);
        assert!(policy.applies_to_resource(&R));
    }

    #[test]
    fn test_applies_to_resource_complex_empty() {
        let policy: TestPolicy = Assertion::Compound(Vec::default());

        assert!(!policy.applies_to_resource(&R));
    }

    #[test]
    fn test_applies_to_resource_complex_unmatched() {
        let Matchers { m_r2, m_a, .. } = Matchers::new();

        let policy = Assertion::Compound(vec![
            Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
        ]);

        assert!(!policy.applies_to_resource(&R));
    }

    #[test]
    fn test_applies_to_resource_complex_matched() {
        let Matchers { m_r2, m_r, m_a, .. } = Matchers::new();

        let policy = Assertion::Compound(vec![
            Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
        ]);

        assert!(policy.applies_to_resource(&R));
    }

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

        let policy: TestPolicy = Assertion::Unconditional(m_r, m_a, Effect::ALLOW);
        assert!(policy.applies_to_action(&A));
        let policy: TestPolicy = Assertion::Unconditional(m_r2, m_a, Effect::ALLOW);
        assert!(policy.applies_to_action(&A));
    }

    #[test]
    fn test_applies_to_action_complex_empty() {
        let policy: TestPolicy = Assertion::Compound(Vec::default());

        assert!(!policy.applies_to_action(&A));
    }

    #[test]
    fn test_applies_to_action_complex_unmatched() {
        let Matchers { m_r, m_a2, .. } = Matchers::new();

        let policy = Assertion::Compound(vec![
            Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
        ]);

        assert!(!policy.applies_to_action(&A));
    }

    #[test]
    fn test_applies_to_action_complex_matched() {
        let Matchers { m_r, m_a, m_a2, .. } = Matchers::new();

        let policy = Assertion::Compound(vec![
            Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a, Effect::ALLOW, true),
            Assertion::Conditional(m_r, m_a2, Effect::ALLOW, true),
        ]);

        assert!(policy.applies_to_action(&A));
    }

    #[test]
    fn test_for_subject() {
        let Matchers { m_r, m_r2, m_a, .. } = Matchers::new();

        let policy = Assertion::Conditional(m_r, m_a, Effect::ALLOW, false);
        let spolicy: Vec<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(
            spolicy,
            vec![SubjectPolicy::Conditional(Effect::ALLOW, false)]
        );

        let policy: TestPolicy = Assertion::Unconditional(m_r, m_a, Effect::DENY);
        let spolicy: Vec<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(spolicy, vec![SubjectPolicy::Unconditional(Effect::DENY)]);

        let policy: TestPolicy = Assertion::Compound(vec![]);
        let spolicy: Vec<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(spolicy, vec![]);

        let policy: TestPolicy =
            Assertion::Compound(vec![Assertion::Unconditional(m_r2, m_a, Effect::ALLOW)]);
        let spolicy: Vec<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(spolicy, vec![]);

        let policy = Assertion::Compound(vec![
            Assertion::Unconditional(m_r, m_a, Effect::ALLOW), // matches
            Assertion::Compound(vec![
                Assertion::Conditional(m_r2, m_a, Effect::ALLOW, true),
                Assertion::Conditional(m_r, m_a, Effect::ALLOW, false), // matches
            ]),
            Assertion::Conditional(m_r, m_a, Effect::DENY, true), // matches
            Assertion::Unconditional(m_r2, m_a, Effect::ALLOW),
        ]);
        let spolicy: HashSet<_> = policy.for_subject(&R, &A).collect();
        assert_eq!(
            spolicy,
            [
                SubjectPolicy::Unconditional(Effect::ALLOW),
                SubjectPolicy::Conditional(Effect::ALLOW, false),
                SubjectPolicy::Conditional(Effect::DENY, true)
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
