// pub struct Subject<Act, Res> {
//     pub action: Act,
//     pub resource: Res,
// }

pub struct Authorization<Subj>(pub Subj, pub bool);

pub struct Authorizations<Azn>(pub Vec<Azn>);

impl<Subj> Authorizations<Authorization<Subj>> {
    pub fn authorized(&self) -> bool {
        !self.0.is_empty() && self.0.iter().all(|azn| azn.1)
    }
}

impl<Subj> FromIterator<Authorization<Subj>> for Authorizations<Authorization<Subj>> {
    fn from_iter<T: IntoIterator<Item = Authorization<Subj>>>(items: T) -> Self {
        Authorizations(items.into_iter().collect())
    }
}

impl<Subj> IntoIterator for Authorizations<Authorization<Subj>> {}

pub trait Oracle {
    type Principal;
    type Subject;
    type Err;

    fn authorized(
        &self,
        principal: &Self::Principal,
        subjects: &[Self::Subject],
    ) -> Result<Authorizations<Azn<Self::Subject>>, Self::Err>;
}
