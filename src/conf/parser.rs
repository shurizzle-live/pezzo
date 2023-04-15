use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use std::{
    ffi::{CString, OsStr, OsString},
    rc::Rc,
};

#[derive(Debug, Clone)]
pub enum Origin {
    User(Vec<CString>),
    Group(Vec<CString>),
}

#[derive(Debug, Clone)]
pub enum Target {
    User(Vec<CString>),
    UserGroup(Vec<CString>, Vec<CString>),
}

#[derive(Debug, Clone)]
pub enum EnvTemplatePart {
    Var(Box<OsStr>),
    Str(Box<OsStr>),
}

#[derive(Debug, Clone)]
pub struct EnvTemplate(Rc<Box<[EnvTemplatePart]>>);

impl EnvTemplate {
    pub fn format(&self) -> Box<OsStr> {
        let mut buf = OsString::new();

        for p in &**self.0 {
            match p {
                EnvTemplatePart::Var(ref name) => {
                    if let Ok(txt) = std::env::var(name) {
                        buf.push(txt);
                    }
                }
                EnvTemplatePart::Str(ref txt) => {
                    buf.push(txt);
                }
            }
        }

        buf.into_boxed_os_str()
    }
}

#[derive(Debug, Clone)]
pub enum Env {
    Unset(Rc<Box<OsStr>>),
    Copy(Rc<Box<OsStr>>),
    Set(Rc<Box<OsStr>>, EnvTemplate),
}

struct Builder {
    origin: Option<Vec<Origin>>,
    target: Option<Vec<Target>>,
    exe: Option<GlobSet>,
    timeout: Option<u64>,
    askpass: Option<bool>,
    keepenv: Option<bool>,
    setenv: Option<Box<[Env]>>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub origin: Vec<Origin>,
    pub target: Option<Vec<Target>>,
    pub timeout: Option<u64>,
    pub askpass: Option<bool>,
    pub exe: Option<GlobSet>,
    pub keepenv: Option<bool>,
    pub setenv: Option<Box<[Env]>>,
}

impl From<Vec<Origin>> for Builder {
    #[inline]
    fn from(origin: Vec<Origin>) -> Self {
        Self {
            origin: Some(origin),
            target: None,
            exe: None,
            timeout: None,
            askpass: None,
            keepenv: None,
            setenv: None,
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
            timeout: None,
            askpass: None,
            keepenv: None,
            setenv: None,
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
            timeout: None,
            askpass: None,
            keepenv: None,
            setenv: None,
        }
    }
}

impl From<Box<[Env]>> for Builder {
    #[inline]
    fn from(value: Box<[Env]>) -> Self {
        Self {
            origin: None,
            target: None,
            exe: None,
            timeout: None,
            askpass: None,
            keepenv: None,
            setenv: Some(value),
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
            timeout,
            askpass,
            keepenv,
            setenv,
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
        if let Some(timeout) = timeout {
            if self.timeout.is_some() {
                return Err("timeout has already been defined");
            }
            self.timeout = Some(timeout);
        }
        if let Some(askpass) = askpass {
            if self.askpass.is_some() {
                return Err("askpass has already been defined");
            }
            self.askpass = Some(askpass);
        }
        if let Some(keepenv) = keepenv {
            if self.keepenv.is_some() {
                return Err("askpass has already been defined");
            }
            self.keepenv = Some(keepenv);
        }
        if let Some(setenv) = setenv {
            if self.setenv.is_some() {
                return Err("askpass has already been defined");
            }
            self.setenv = Some(setenv);
        }
        Ok(())
    }

    #[inline]
    pub fn build(self) -> Result<Rule, &'static str> {
        if let Some(origin) = self.origin {
            Ok(Rule {
                origin,
                target: self.target,
                timeout: self.timeout,
                askpass: self.askpass,
                exe: self.exe,
                keepenv: self.keepenv,
                setenv: self.setenv,
            })
        } else {
            Err("origin not defined in rule")
        }
    }

    #[inline]
    pub fn with_timeout(timeout: u64) -> Self {
        Self {
            origin: None,
            target: None,
            exe: None,
            askpass: None,
            timeout: Some(timeout),
            keepenv: None,
            setenv: None,
        }
    }

    #[inline]
    pub fn with_askpass(ask: bool) -> Self {
        Self {
            origin: None,
            target: None,
            exe: None,
            timeout: None,
            askpass: Some(ask),
            keepenv: None,
            setenv: None,
        }
    }

    #[inline]
    pub fn with_keepenv(keepenv: bool) -> Self {
        Self {
            origin: None,
            target: None,
            exe: None,
            timeout: None,
            askpass: None,
            keepenv: Some(keepenv),
            setenv: None,
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
            / t:timeout_statement() { t }
            / a:askpass_statement() { a }
            / k:keepenv_statement() { k }
            / e:setenv_statement() { e }

        rule origin_statement() -> Builder
            = "origin" _ "=" _ o:origin_exp() _ ";" { o.into() }

        rule target_statement() -> Builder
            = "target" _ "=" _ t:target_exp() _ ";" { t.into() }

        rule exe_statement() -> Builder
            = "exe" _ "=" _ e:exe_expr() _ ";" { e.into() }

        rule timeout_statement() -> Builder
            = "timeout" _ "=" _ i:u64_literal() _ ";" { Builder::with_timeout(i) }

        rule askpass_statement() -> Builder
            = "askpass" _ "=" _ b:bool_literal() _ ";" { Builder::with_askpass(b) }

        rule keepenv_statement() -> Builder
            = "keepenv" _ "=" _ b:bool_literal() _ ";" { Builder::with_keepenv(b) }

        rule setenv_statement() -> Builder
            = "setenv" _ "=" _ "{" _ e:env_expr() _ [b',']? _ "}" _ ";" { e.into() }

        rule var_name_() -> OsString
            = name:$([b'A'..=b'Z' | b'a'..=b'z' | b'_'][b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'0'..=b'9']*) {
                OsString::from(unsafe { std::str::from_utf8_unchecked(name) }.to_string())
            }
        rule var_name() -> Rc<Box<OsStr>>
            = name:var_name_() { Rc::new(name.into_boxed_os_str()) }

        rule env_unset() -> Env
            = "-" n:var_name() { Env::Unset(n) }

        rule env_copy() -> Env
            = n:var_name() { Env::Copy(n) }

        rule env_set() -> Env
            = n:var_name() "=\"" t:var_template() [b'"'] { Env::Set(n, t) }

        rule var_template() -> EnvTemplate
            = p:var_template_part()* { EnvTemplate(Rc::new(p.into_boxed_slice())) }

        rule var_template_part_str_char() -> u8
            = [b'\\'] c:[b'$' | b'"' | b'\\'] { c }
            / c:[^ b'\0' | b'$' | b'"'] { c }

        rule var_template_part() -> EnvTemplatePart
            = [b'$'] n:var_name_() { EnvTemplatePart::Var(n.into_boxed_os_str()) }
            / "${" n:var_name_() [b'}'] { EnvTemplatePart::Var(n.into_boxed_os_str()) }
            / s:var_template_part_str_char()+ {?
                Ok(EnvTemplatePart::Str(OsString::from(String::from_utf8(s).map_err(|_| "invalid utf8")?).into_boxed_os_str()))
            }

        rule env() -> Env
            = e:env_unset() { e }
            / e:env_set() { e }
            / e:env_copy() { e }

        rule env_expr_cont() -> Env
            = "," _ e:env() _ { e }

        rule env_expr() -> Box<[Env]>
            = lh:env() _ rh:env_expr_cont()* {
                let mut rh = rh;
                rh.insert(0, lh);
                rh.into_boxed_slice()
            }
            / lh:env() {
                vec![lh].into_boxed_slice()
            }

        rule bool_literal() -> bool
            = "true" { true }
            / "false" { false }

        rule u64_literal() -> u64
            = i:$(([b'1'..=b'9'][b'0'..=b'9']*) / [b'0']) {?
                std::str::from_utf8(i)
                    .map_err(|_| "invalid integer")?
                    .parse::<u64>()
                    .map_err(|_| "invalid integer")
            }

        rule exe_char() -> u8
            = [b'\\'] c:[b' ' | b'|' | b';' | b':' | b'\\'] { c }
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
            = [b':'] _ group:group_exp() { Origin::Group(group) }
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
