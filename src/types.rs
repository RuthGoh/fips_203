use crate::Q;
use zeroize::ZeroizeOnDrop;
use core::{ops,cmp};

pub(crate) fn ss_to_bytes<const LEN:usize>(s:&[S]) -> [u8;LEN] {
    core::array::from_fn(|i| s[i].0)
}
pub(crate) fn bytes_to_ss<const LEN:usize>(b:&[u8]) -> [S;LEN] {
    core::array::from_fn(|i| S(b[i]))
}


#[derive(Clone,ZeroizeOnDrop)]
pub(crate) struct S(pub u8);
impl ops::BitOrAssign<S> for S {
    fn bitor_assign(&mut self, rhs:S) {
        self.0 |= rhs.0;
    }
}
impl ops::Shr<u8> for &S {
    type Output = S;
    fn shr(self, rhs:u8) -> S {
        S(self.0 >> rhs)
    }
}
impl ops::Shr<usize> for &S {
    type Output = S;
    fn shr(self, rhs:usize) -> S {
        S(self.0 >> rhs)
    }
}
impl ops::BitAnd<u8> for S {
    type Output = S;
    fn bitand(self, rhs:u8) -> S {
        S(self.0 & rhs)
    }
}
impl cmp::PartialEq<S> for S {
    fn eq(&self, other: &S) -> bool {
        self.0 == other.0
    }
}
impl ops::AddAssign<u8> for S {
    fn add_assign(&mut self, rhs: u8) {
        self.0 += rhs
    }
}
impl ops::AddAssign<S> for S {
    fn add_assign(&mut self, rhs: S) {
        self.0 += rhs.0
    }
}

#[derive(Clone,ZeroizeOnDrop)]
pub(crate) struct Z (pub u16);
impl Z {
    pub(crate) fn rem(self, rhs:u16) -> Z {
        Z(self.0 % rhs)
    }
}
impl ops::Add<&Z> for &Z {
    type Output = Z;
    fn add(self, rhs:&Z) -> Z {
        Z((self.0 + rhs.0)%Q)
    }
}
impl ops::Mul<&Z> for &Z {
    type Output = Z;
    fn mul(self, rhs:&Z) -> Z {
        match self.0.checked_mul(rhs.0) {
            Some(x) => Z(x%Q),
            None => {
                if self.0%2 == 0 {&(&Z(self.0/2)*&Z(rhs.0))*&Z(2)}
                else {&(&Z(self.0/2)*&Z(rhs.0)) + &(&Z((self.0+1)/2)*rhs)}
            }
        }
    }
}
impl ops::Sub<&Z> for &Z {
    type Output = Z;
    fn sub(self, rhs:&Z) -> Z {
        match self.0.checked_sub(rhs.0) {
            Some(x) => Z(x),
            None => Z(Q+self.0-rhs.0)
        }
    }
}
impl ops::Div<u16> for Z {
    type Output = Z;
    fn div(self, rhs:u16) -> Z {
        Z(self.0/rhs)
    }
}
impl ops::Shl<u8> for Z {
    type Output = S;
    fn shl(self, rhs: u8) -> S {
        S((self.0 as u8) << rhs)
    }
}