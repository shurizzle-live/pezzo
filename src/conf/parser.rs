use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use std::ffi::CString;

#[derive(Debug, Clone)]
pub enum Origin {
    User(Vec<CString>),
    Group(Vec<CString>),
    UserGroup(Vec<CString>, Vec<CString>),
}

#[derive(Debug, Clone)]
pub enum Target {
    User(Vec<CString>),
    UserGroup(Vec<CString>, Vec<CString>),
}

struct Builder {
    origin: Option<Vec<Origin>>,
    target: Option<Vec<Target>>,
    exe: Option<GlobSet>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub origin: Vec<Origin>,
    pub target: Option<Vec<Target>>,
    pub exe: Option<GlobSet>,
}

impl From<Vec<Origin>> for Builder {
    #[inline]
    fn from(origin: Vec<Origin>) -> Self {
        Self {
            origin: Some(origin),
            target: None,
            exe: None,
        }
    }
}

impl From<Vec<Target>> for Builder {
    #[inline]
    fn from(target: Vec<Target>) -> Self {
        Self {
            origin: None,
            target: Some(target),
            exe: None,
        }
    }
}

impl From<GlobSet> for Builder {
    #[inline]
    fn from(exe: GlobSet) -> Self {
        Self {
            origin: None,
            target: None,
            exe: Some(exe),
        }
    }
}

impl Builder {
    pub fn merge(
        &mut self,
        Self {
            origin,
            target,
            exe,
        }: Self,
    ) -> Result<(), &'static str> {
        if let Some(origin) = origin {
            if self.origin.is_some() {
                return Err("origin has already been defined");
            }
            self.origin = Some(origin);
        }
        if let Some(target) = target {
            if self.target.is_some() {
                return Err("target has already been defined");
            }
            self.target = Some(target);
        }
        if let Some(exe) = exe {
            if self.exe.is_some() {
                return Err("exe has already been defined");
            }
            self.exe = Some(exe);
        }
        Ok(())
    }

    #[inline]
    pub fn build(self) -> Result<Rule, &'static str> {
        if let Some(origin) = self.origin {
            Ok(Rule {
                origin,
                target: self.target,
                exe: self.exe,
            })
        } else {
            Err("origin not defined in rule")
        }
    }
}

peg::parser! {
    grammar config() for [u8] {
        use std::ffi::CString;

        rule ws() = quiet!{[b' ' | b'\n' | b'\t']+}
        rule eof() = quiet!{![_]}
        rule eol() = quiet!{[b'\n']}
        rule comment() = quiet!{[b'#'] [^ b'\n']* (eol() / eof())}
        rule ignored() = quiet!{ws()/comment()}
        rule _ = quiet!{ignored()*}

        pub rule parse() -> Vec<Rule>
            = rules:parse_rule()* { rules }

        rule parse_rule() -> Rule
            = _ "rule" _ "{" _ r:rule_statements() _ "}" _ { r }

        rule _rule_statements() -> Vec<Builder>
            = lh:rule_statement() _ rh:_rule_statements() { let mut rh = rh; rh.insert(0, lh); rh }
            / rul:rule_statement() { vec![rul] }

        rule rule_statements() -> Rule
            = rules:_rule_statements() {?
                if rules.is_empty() {
                    unreachable!();
                }

                let mut rules = rules;
                let mut acc = rules.remove(0);
                for rule in rules {
                    acc.merge(rule)?;
                }
                acc.build()
            }

        rule rule_statement() -> Builder
            = o:origin_statement() { o }
            / t:target_statement() { t }
            / e:exe_statement() { e }

        rule origin_statement() -> Builder
            = "origin" _ "=" _ o:origin_exp() _ ";" { o.into() }

        rule target_statement() -> Builder
            = "target" _ "=" _ t:target_exp() _ ";" { t.into() }

        rule exe_statement() -> Builder
            = "exe" _ "=" _ e:exe_expr() _ ";" { e.into() }

        rule exe_char() -> u8
            = [b'\\'] c:[b' ' | b'|' | b';' | b':'] { c }
            / c:[^ b'\0' | b' ' | b'|' | b';' | b':'] { c }

        rule exe() -> Glob
            = name:(exe_char()+) {?
                GlobBuilder::new(
                        std::str::from_utf8(name.as_slice())
                            .map_err(|_| "invalid utf8")?)
                    .literal_separator(true)
                    .build()
                    .map_err(|_| "invalid glob")
            }

        rule exe_expr_cont() -> Glob
            = [b'|'] _ e:exe() _ { e }

        rule exe_expr() -> GlobSet
            = lh:exe() _ rh:exe_expr_cont()* {?
                let mut builder = GlobSetBuilder::new();
                builder.add(lh);
                for g in rh {
                    builder.add(g);
                }
                builder.build().map_err(|_| "invalid exe glob")
            }
            / name:exe() {? GlobSetBuilder::new().add(name).build().map_err(|_| "invalid exe glob") }

        rule user() -> CString
            = name:$([b'A'..=b'Z'|b'a'..=b'z'|b'_'][b'A'..=b'Z'|b'a'..=b'z'|b'0'..=b'9'|b'_']+) { unsafe { CString::from_vec_unchecked(name.to_vec()) } }

        rule group() -> CString
            = name:$([b'A'..=b'Z'|b'a'..=b'z'|b'_'][b'A'..=b'Z'|b'a'..=b'z'|b'0'..=b'9'|b'_']+) { unsafe { CString::from_vec_unchecked(name.to_vec()) } }

        rule user_exp_cont() -> CString
            = [b'|'] _ user:user() _ { user }

        rule user_exp() -> Vec<CString>
            = [b'('] _ lh:user() _ rh:user_exp_cont()* [b')'] { let mut rh = rh; rh.insert(0, lh); rh }
            / user:user() { vec![user] }

        rule group_exp_cont() -> CString
            = [b'|'] _ group:group() _ { group }

        rule group_exp() -> Vec<CString>
            = [b'('] _ lh:group() _ rh:group_exp_cont()* [b')'] { let mut rh = rh; rh.insert(0, lh); rh }
            / group:group() { vec![group] }

        rule origin() -> Origin
            = user:user_exp() _ [b':'] _ group:group_exp() { Origin::UserGroup(user, group) }
            / [b':'] _ group:group_exp() { Origin::Group(group) }
            / user:user_exp() { Origin::User(user) }

        rule origin_exp_cont() -> Origin
            = [b'|'] _ o:origin() _ { o }

        rule origin_exp() -> Vec<Origin>
            = lh:origin() _ rh:origin_exp_cont()* { let mut rh = rh; rh.insert(0, lh); rh }
            / o:origin() { vec![o] }

        rule target() -> Target
            = users:user_exp() _ [b':'] _ groups:group_exp() { Target::UserGroup(users, groups) }
            / users:user_exp() { Target::User(users) }

        rule target_exp_cont() -> Target
            = [b'|'] _ t:target() _ { t }

        rule target_exp() -> Vec<Target>
            = lh:target() _ rh:target_exp_cont()* { let mut rh = rh; rh.insert(0, lh); rh }
            / t:target() { vec![t] }
    }
}

pub use config::parse;
