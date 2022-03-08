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

using namespace std;
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

void base_expr_visitor::visit(unary_check_expr* e){ }

expr* libsinsp::filter::ast::clone(expr* e)
{  
    struct clone_visitor: public expr_visitor
    {   
        expr* m_last_node;

        inline void visit(and_expr* e) 
        {
            vector<expr*> children;
            for (auto &c: e->children)
            {
                c->accept(this);
                children.push_back(m_last_node);
            }
            m_last_node = new and_expr(children);
        }

        inline void visit(or_expr* e)
        {
            vector<expr*> children;
            for (auto &c: e->children)
            {
                c->accept(this);
                children.push_back(m_last_node);
            }
            m_last_node = new or_expr(children);
        }

        inline void visit(not_expr* e)
        {
            e->child->accept(this);
            m_last_node = new not_expr(m_last_node);
        }

        inline void visit(binary_check_expr* e)
        {
            e->value->accept(this);
            m_last_node = new binary_check_expr(e->field, e->arg, e->op, m_last_node);
        }

        inline void visit(unary_check_expr* e)
        {
            m_last_node = new unary_check_expr(e->field, e->arg, e->op);
        }

        inline void visit(value_expr* e)
        {
            m_last_node = new value_expr(e->value);
        }

        inline void visit(list_expr* e)
        {
            m_last_node = new list_expr(e->values);
        }
    } visitor;

    visitor.m_last_node = NULL;
    e->accept(&visitor);
    return visitor.m_last_node;
}