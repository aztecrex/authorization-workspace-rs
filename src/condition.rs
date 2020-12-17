


pub trait Environment {
    type Err;
    type CExp;

    fn test_condition (&self, exp: &Self::CExp) -> Result<bool, Self::Err>;

}



