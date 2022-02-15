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

#pragma once

#include <vector>
#include <string>
#include <algorithm>

namespace libsinsp {
namespace filter {

using namespace std;

namespace ast {

struct expr;
struct and_expr;
struct or_expr;
struct not_expr;
struct value_expr;
struct list_expr;
struct unary_check_expr;
struct binary_check_expr;

/*!
    \brief Base interface of AST visitors
*/
struct expr_visitor
{
    virtual void visit(and_expr&) = 0;
    virtual void visit(or_expr&) = 0;
    virtual void visit(not_expr&) = 0;
    virtual void visit(value_expr&) = 0;
    virtual void visit(list_expr&) = 0;
    virtual void visit(unary_check_expr&) = 0;
    virtual void visit(binary_check_expr&) = 0;
};

/*!
    \brief Base interface of AST hierarchy
*/
struct expr
{
    virtual void accept(expr_visitor&) = 0;
    virtual bool is_equal(const expr* other) const = 0;
};

/*!
    \brief Comparator for AST hierarchy
*/
inline bool compare(const expr* left, const expr* right)
{
    return left->is_equal(right);
};

struct and_expr: expr
{
    inline and_expr() { }

    inline and_expr(vector<expr*> c): children(c) { }

    inline ~and_expr()
    {
        for (auto &c : children)
        {
            delete c;
        }
    }

    inline void accept(expr_visitor& v) override
    {
        v.visit(*this);
    };

    inline bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const and_expr*>(other);
        return o != nullptr && equal(
            children.begin(), children.end(), 
            o->children.begin(), compare);
    }

    vector<expr*> children;
};

struct or_expr: expr
{
    inline or_expr() { }

    inline or_expr(vector<expr*> c): children(c) { }

    inline ~or_expr()
    {
        for (auto &c : children)
        {
            delete c;
        }
    }

    inline void accept(expr_visitor& v) override
    {
        v.visit(*this);
    };

    inline bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const or_expr*>(other);
        return o != nullptr && equal(
            children.begin(), children.end(), 
            o->children.begin(), compare);
    }

    vector<expr*> children;
};

struct not_expr: expr
{
    inline not_expr() { }

    inline not_expr(expr* c): child(c) { }

    inline ~not_expr()
    {
        delete child;
    }

    inline void accept(expr_visitor& v) override
    {
        v.visit(*this);
    };

    inline bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const not_expr*>(other);
        return o != nullptr && child->is_equal(o->child);
    }

    expr* child;
};

struct value_expr: expr
{
    inline value_expr() { }

    inline value_expr(string v): value(v) { }

    inline void accept(expr_visitor& v) override
    {
        v.visit(*this);
    };

    inline bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const value_expr*>(other);
        return o != nullptr && value == o->value;
    }

    string value;
};

struct list_expr: expr
{
    inline list_expr() { }

    inline list_expr(vector<string>v): values(v) { }

    inline void accept(expr_visitor& v) override
    {
        v.visit(*this);
    };

    inline bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const list_expr*>(other);
        return o != nullptr && values == o->values;
    }

    vector<string> values;
};

struct unary_check_expr: expr
{
    inline unary_check_expr() { }

    inline unary_check_expr(
        string f,
        string a,
        string o): field(f), arg(a), op(o) { }

    inline void accept(expr_visitor& v) override
    {
        v.visit(*this);
    };

    inline bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const unary_check_expr*>(other);
        return o != nullptr && field == o->field
            && arg == o->arg && op == o->op;
    }

    string field;
    string arg;
    string op;
};

struct binary_check_expr: expr
{
    inline binary_check_expr() { }

    inline binary_check_expr(
        string f,
        string a,
        string o,
        expr* v): field(f), arg(a), op(o), value(v) { }

    inline ~binary_check_expr()
    {
        delete value;
    }

    inline void accept(expr_visitor& v) override
    {
        v.visit(*this);
    };

    inline bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const binary_check_expr*>(other);
        return o != nullptr && field == o->field
            && arg == o->arg && op == o->op && value->is_equal(o->value);
    }

    string field;
    string arg;
    string op;
    expr* value;
};

}
}
}