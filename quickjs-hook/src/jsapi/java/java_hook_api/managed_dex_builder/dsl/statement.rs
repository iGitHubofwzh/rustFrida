use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_statements(&mut self, stop_on_brace: bool) -> Result<Vec<DslStmt>, String> {
        let mut stmts = Vec::new();
        loop {
            self.skip_ws();
            if self.is_eof() {
                if stop_on_brace {
                    return Err(self.err("expected '}'"));
                }
                break;
            }
            if stop_on_brace && self.peek() == Some('}') {
                self.expect_char('}')?;
                break;
            }
            let stmt = self.parse_statement()?;
            stmts.push(stmt);
        }
        Ok(stmts)
    }

    pub(super) fn parse_block(&mut self) -> Result<Vec<DslStmt>, String> {
        self.skip_ws();
        self.expect_char('{')?;
        self.with_local_scope(|parser| parser.parse_statements(true))
    }

    pub(super) fn parse_statement_body(&mut self) -> Result<Vec<DslStmt>, String> {
        self.skip_ws();
        if self.peek() == Some('{') {
            self.parse_block()
        } else {
            self.with_local_scope(|parser| Ok(vec![parser.parse_statement()?]))
        }
    }

    fn parse_statement(&mut self) -> Result<DslStmt, String> {
        self.skip_ws();
        if self.peek_ident("return") {
            self.expect_ident("return")?;
            self.skip_ws();
            if self.peek_ident("orig") {
                self.expect_ident("orig")?;
                let args = self.parse_orig_args()?;
                self.skip_ws();
                self.expect_char(';')?;
                return Ok(DslStmt::ReturnOrig { args });
            }
            let value = if self.peek() == Some(';') {
                None
            } else {
                Some(self.parse_value_arg()?)
            };
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::ReturnValue { value });
        }
        if self.peek_ident("throw") {
            self.expect_ident("throw")?;
            let value = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Throw { value });
        }
        if self.peek_ident("if") {
            return self.parse_js_if_statement();
        }
        if self.peek_ident("while") {
            return self.parse_js_while_statement();
        }
        if self.peek_ident("do") {
            return self.parse_js_do_while_statement();
        }
        if self.peek_ident("for") {
            return self.parse_js_for_statement();
        }
        if self.peek_ident("switch") {
            return self.parse_js_switch_statement();
        }
        if self.peek_ident("try") {
            return self.parse_js_try_catch_statement();
        }
        if self.peek_ident("break") {
            self.expect_ident("break")?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Break);
        }
        if self.peek_ident("continue") {
            self.expect_ident("continue")?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Continue);
        }
        if self.peek_op("++") || self.peek_op("--") {
            let delta = if self.peek_op("++") {
                self.expect_op("++")?;
                1
            } else {
                self.expect_op("--")?;
                -1
            };
            let name = self.parse_ident()?;
            let name = self.resolve_local_name_or_source(name);
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(self.local_increment_stmt(name, delta));
        }

        let name = self.parse_ident()?;
        self.skip_ws();
        if name == "let" && self.peek() != Some('(') {
            return self.parse_js_let_statement();
        }
        if name == "new" && self.peek() != Some('(') {
            let stmt = self.parse_js_new_statement()?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(stmt);
        }
        if name == "count" && self.peek() == Some('(') {
            self.expect_char('(')?;
            self.skip_ws();
            let counter_name = self.parse_string_arg()?;
            self.skip_ws();
            self.expect_char(')')?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Count { name: counter_name });
        }
        if self.peek() == Some('=') {
            self.expect_char('=')?;
            let value = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            let name = self.resolve_local_name_or_source(name);
            return Ok(DslStmt::Assign { name, value });
        }
        if let Some(op) = self.peek_compound_assign_op() {
            self.consume_compound_assign_op(op)?;
            let rhs = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            let name = self.resolve_local_name_or_source(name);
            return Ok(self.local_compound_assign_stmt(name, op, rhs));
        }
        if self.peek_op("++") || self.peek_op("--") {
            let delta = if self.peek_op("++") {
                self.expect_op("++")?;
                1
            } else {
                self.expect_op("--")?;
                -1
            };
            self.skip_ws();
            self.expect_char(';')?;
            let name = self.resolve_local_name_or_source(name);
            return Ok(self.local_increment_stmt(name, delta));
        }
        if self.peek() == Some('.') || self.peek() == Some('[') || self.peek_ident("as") {
            let value = self.parse_value_from_ident(name)?;
            self.skip_ws();
            if self.peek() == Some('=') {
                self.expect_char('=')?;
                let rhs = self.parse_value_arg()?;
                self.skip_ws();
                self.expect_char(';')?;
                return match value {
                    DslValue::FieldGet { stmt, is_static } => {
                        let mut stmt = *stmt;
                        stmt.value = Some(rhs);
                        Ok(DslStmt::FieldWrite { stmt, is_static })
                    }
                    DslValue::ArrayGet {
                        array,
                        index,
                        type_name,
                    } => Ok(DslStmt::ArrayPut {
                        array: *array,
                        index: *index,
                        type_name,
                        value: rhs,
                    }),
                    _ => Err(self.err("only fields and array elements can be assigned")),
                };
            }
            if let Some(op) = self.peek_compound_assign_op() {
                self.consume_compound_assign_op(op)?;
                let rhs = self.parse_value_arg()?;
                self.skip_ws();
                self.expect_char(';')?;
                return self.compound_assign_value_stmt(value, op, rhs);
            }
            if self.peek_op("++") || self.peek_op("--") {
                let delta = if self.peek_op("++") {
                    self.expect_op("++")?;
                    1
                } else {
                    self.expect_op("--")?;
                    -1
                };
                self.skip_ws();
                self.expect_char(';')?;
                return self.increment_value_stmt(value, delta);
            }
            self.expect_char(';')?;
            return value
                .into_statement()
                .ok_or_else(|| self.err("only method calls and field reads can be used as expression statements"));
        }
        Err(self.err(&format!("unknown managed DSL statement '{}'", name)))
    }
}
