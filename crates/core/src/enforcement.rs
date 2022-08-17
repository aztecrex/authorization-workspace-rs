// pub struct Subject<Act, Res> {
//     pub action: Act,
//     pub resource: Res,
// }

pub struct Azn<Subj>(pub Subj, pub bool);

pub struct Authorizations<Azn>(pub Vec<Azn>);

impl<Subj> FromIterator<Azn<Subj>> for Authorizations<Azn<Subj>> {
    fn from_iter<T: IntoIterator<Item = Azn<Subj>>>(items: T) -> Self {
        Authorizations(items.into_iter().collect())
    }
}

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
