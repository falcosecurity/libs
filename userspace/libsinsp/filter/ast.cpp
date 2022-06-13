/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "ast.h"
#include "escaping.h"

using namespace libsinsp::filter::ast;

void base_expr_visitor::visit(and_expr* e)
{
    for(auto &c: e->children)
    {
        if (m_should_stop_visit)
        {
            return;
        }
        c->accept(this);
    }
}

void base_expr_visitor::visit(or_expr* e)
{
    for(auto &c: e->children)
    {
        if (m_should_stop_visit)
        {
            return;
        }
        c->accept(this);
    }
}

void base_expr_visitor::visit(not_expr* e)
{
    if (!m_should_stop_visit)
    {
        e->child->accept(this);
    }
}

void base_expr_visitor::visit(binary_check_expr* e)
{
    if (!m_should_stop_visit)
    {
        e->value->accept(this);
    }
}

void base_expr_visitor::visit(value_expr* e) { }

void base_expr_visitor::visit(list_expr* e) { }

void base_expr_visitor::visit(unary_check_expr* e) { }

void string_visitor::visit_logical_op(const char *op, std::vector<expr*> &children)
{
	bool first = true;

	m_str += "(";

	for (auto &c : children)
	{
		if(!first)
		{
			m_str += " ";
			m_str += op;
			m_str += " ";
		}
		first = false;
		c->accept(this);
	}
	m_str += ")";
}

void string_visitor::visit(and_expr* e)
{
	visit_logical_op("and", e->children);
}

void string_visitor::visit(or_expr* e)
{
	visit_logical_op("or", e->children);
}

void string_visitor::visit(not_expr* e)
{
	m_str += "not ";

	e->child->accept(this);
}

void string_visitor::visit(value_expr* e)
{
	if(escape_next_value)
	{
		m_str += libsinsp::filter::escape_str(e->value);
	}
	else
	{
		m_str += e->value;
	}

	escape_next_value = false;
}

void string_visitor::visit(list_expr* e)
{
	bool first = true;

	m_str += "(";

	for(auto &val : e->values)
	{
		if(!first)
		{
			m_str += ", ";
		}
		first = false;
		m_str += libsinsp::filter::escape_str(val);
	}

	m_str += ")";
}
void string_visitor::visit(unary_check_expr* e)
{
	m_str += e->field;

	if(e->arg != "")
	{
		m_str += "[" + libsinsp::filter::escape_str(e->arg) + "]";
	}

	m_str += " ";
	m_str += e->op;
}

void string_visitor::visit(binary_check_expr* e)
{
	m_str += e->field;

	if(e->arg != "")
	{
	        m_str += "[" + libsinsp::filter::escape_str(e->arg) + "]";
	}

	m_str += " ";
	m_str += e->op;
	m_str += " ";

	escape_next_value = true;

	e->value->accept(this);
}

const std::string& string_visitor::as_string()
{
	return m_str;
}

std::string libsinsp::filter::ast::as_string(ast::expr &e)
{
	string_visitor sv;

	e.accept(&sv);

	return sv.as_string();
}

expr* libsinsp::filter::ast::clone(expr* e)
{  
    struct clone_visitor: public expr_visitor
    {   
        expr* m_last_node;

        void visit(and_expr* e) override
        {
            std::vector<expr*> children;
            for (auto &c: e->children)
            {
                c->accept(this);
                children.push_back(m_last_node);
            }
            m_last_node = new and_expr(children);
        }

        void visit(or_expr* e) override
        {
            std::vector<expr*> children;
            for (auto &c: e->children)
            {
                c->accept(this);
                children.push_back(m_last_node);
            }
            m_last_node = new or_expr(children);
        }

        void visit(not_expr* e) override
        {
            e->child->accept(this);
            m_last_node = new not_expr(m_last_node);
        }

        void visit(binary_check_expr* e) override
        {
            e->value->accept(this);
            m_last_node = new binary_check_expr(
                e->field, e->arg, e->op, m_last_node);
        }

        void visit(unary_check_expr* e) override
        {
            m_last_node = new unary_check_expr(e->field, e->arg, e->op);
        }

        void visit(value_expr* e) override
        {
            m_last_node = new value_expr(e->value);
        }

        void visit(list_expr* e) override
        {
            m_last_node = new list_expr(e->values);
        }
    } visitor;

    visitor.m_last_node = NULL;
    e->accept(&visitor);
    return visitor.m_last_node;
}