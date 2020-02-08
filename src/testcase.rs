use crate::lex::*;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

#[derive(PartialEq, Debug)]
pub struct Register {
    pub reg: unicorn::RegisterARM,
}

impl Eq for Register {}
impl Hash for Register {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u32(self.reg as u32);
    }
}

#[derive(Debug)]
pub struct TestCase<'i> {
    pub name: &'i str,
    pub setup: HashMap<Register, i32>,
    pub target: &'i str,
    pub check: HashMap<Register, i32>,
}

impl<'i> TestCase<'i> {
    pub fn parse(input: &'i str) -> Result<TestCase<'i>, LexError> {
        complete(Self::lex(input))
    }
}

impl<'i> Lex<'i> for TestCase<'i> {
    fn lex(input: &'i str) -> LexResult<TestCase<'i>> {
        let input = expect(input, "test:")?;
        let input = skip_space(input);
        let (name, input) = take_while(input, "test name", |c| c != '\n')?;
        let input = skip_space(input);
        let input = expect(input, "setup:")?;
        let (setup, input) = HashMap::lex(input)?;
        let input = expect(input, "call:")?;
        let input = skip_space(input);
        let (sym, input) = take_while(input, "symbol name", |c| !c.is_whitespace())?;
        let input = skip_space(input);
        let input = expect(input, "check:")?;
        let input = skip_space(input);
        let (check, input) = HashMap::lex(input)?;
        Ok((
            TestCase {
                name: name,
                setup: setup,
                target: sym,
                check: check,
            },
            input,
        ))
    }
}

impl<'i> Lex<'i> for HashMap<Register, i32> {
    fn lex(input: &'i str) -> LexResult<HashMap<Register, i32>> {
        let mut input = skip_space(input);
        let mut map = HashMap::new();
        loop {
            if let Ok((reg, ix)) = Register::lex(input) {
                input = skip_space(ix);
                input = expect(input, "=")?;
                input = skip_space(input);
                let (val, ix) = i32::lex(input)?;
                input = skip_space(ix);
                map.insert(reg, val);
            } else {
                return Ok((map, input));
            }
        }
    }
}

impl<'i> Lex<'i> for Register {
    fn lex(input: &'i str) -> LexResult<Register> {
        let (reg, ix) = take_while(input, "register", |c| !c.is_whitespace())?;

        match &*reg {
            "r0" => Ok((
                Register {
                    reg: unicorn::RegisterARM::R0,
                },
                ix,
            )),
            "r1" => Ok((
                Register {
                    reg: unicorn::RegisterARM::R1,
                },
                ix,
            )),
            "r2" => Ok((
                Register {
                    reg: unicorn::RegisterARM::R2,
                },
                ix,
            )),
            "r3" => Ok((
                Register {
                    reg: unicorn::RegisterARM::R3,
                },
                ix,
            )),
            "r4" => Ok((
                Register {
                    reg: unicorn::RegisterARM::R4,
                },
                ix,
            )),
            "r5" => Ok((
                Register {
                    reg: unicorn::RegisterARM::R5,
                },
                ix,
            )),
            "r6" => Ok((
                Register {
                    reg: unicorn::RegisterARM::R6,
                },
                ix,
            )),
            "r7" => Ok((
                Register {
                    reg: unicorn::RegisterARM::R7,
                },
                ix,
            )),
            _ => Err((LexErrorKind::ExpectedName("register"), input)),
        }
    }
}
