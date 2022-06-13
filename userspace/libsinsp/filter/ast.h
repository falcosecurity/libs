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
#include "../sinsp_public.h"

namespace libsinsp {
namespace filter {
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
    \brief Interface of AST visitors
*/
struct SINSP_PUBLIC expr_visitor
{
    virtual ~expr_visitor() = default;
    virtual void visit(and_expr*) = 0;
    virtual void visit(or_expr*) = 0;
    virtual void visit(not_expr*) = 0;
    virtual void visit(value_expr*) = 0;
    virtual void visit(list_expr*) = 0;
    virtual void visit(unary_check_expr*) = 0;
    virtual void visit(binary_check_expr*) = 0;
};

/*!
    \brief Base implementation for AST visitors, that traverses
    the tree without doing anything. This way, subclasses can
    avoid overriding empty methods if they are not interested
    in a specific type of AST node
*/
struct SINSP_PUBLIC base_expr_visitor: public expr_visitor
{
public:
    /*!
        \brief Can be set to true by subclasses to instruct the
        visitor that the exploration can be stopped, so
        that the recursion gets rewinded and no more nodes
        are explored.
    */
    inline void stop(bool v)
    {
        m_should_stop_visit = v;
    }

    virtual void visit(and_expr*) override;
    virtual void visit(or_expr*) override;
    virtual void visit(not_expr*) override;
    virtual void visit(value_expr*) override;
    virtual void visit(list_expr*) override;
    virtual void visit(unary_check_expr*) override;
    virtual void visit(binary_check_expr*) override;

private:
    bool m_should_stop_visit = false;
};

/*!
    \brief A visitor that builds a string as it traverses the
    ast. Used to convert to strings.
*/
struct SINSP_PUBLIC string_visitor: public expr_visitor
{
public:
	virtual ~string_visitor() = default;
	virtual void visit(and_expr*) override;
	virtual void visit(or_expr*) override;
	virtual void visit(not_expr*) override;
	virtual void visit(value_expr*) override;
	virtual void visit(list_expr*) override;
	virtual void visit(unary_check_expr*) override;
	virtual void visit(binary_check_expr*) override;

	const std::string& as_string();

protected:

	void visit_logical_op(const char *op, std::vector<expr*> &children);

	// If true, the next call to vist(value_expr*) will escape the
	// value. This occurs for any right hand side of a binary check.
	bool escape_next_value = false;

	std::string m_str;
};

/*!
    \brief Base interface of AST hierarchy
*/
struct SINSP_PUBLIC expr
{
    virtual ~expr() = default;
    virtual void accept(expr_visitor*) = 0;
    virtual bool is_equal(const expr* other) const = 0;
};

/*!
    \brief Compares two ASTs, returns true if they are deep equal
*/
inline bool compare(const expr* left, const expr* right)
{
    return left->is_equal(right);
};

struct SINSP_PUBLIC and_expr: expr
{
    and_expr() { }

    explicit and_expr(const std::vector<expr*>& c): children(c) { }

    ~and_expr()
    {
        for (auto &c : children)
        {
            delete c;
        }
    }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const and_expr*>(other);
        return o != nullptr && std::equal(
            children.begin(), children.end(), 
            o->children.begin(), compare);
    }

    std::vector<expr*> children;
};

struct SINSP_PUBLIC or_expr: expr
{
    or_expr() { }

    explicit or_expr(const std::vector<expr*>& c): children(c) { }

    ~or_expr()
    {
        for (auto &c : children)
        {
            delete c;
        }
    }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const or_expr*>(other);
        return o != nullptr && std::equal(
            children.begin(), children.end(), 
            o->children.begin(), compare);
    }

    std::vector<expr*> children;
};

struct SINSP_PUBLIC not_expr: expr
{
    not_expr() { }

    explicit not_expr(expr* c): child(c) { }

    ~not_expr()
    {
        delete child;
    }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const not_expr*>(other);
        return o != nullptr && child->is_equal(o->child);
    }

    expr* child;
};

struct SINSP_PUBLIC value_expr: expr
{
    value_expr() { }

    explicit value_expr(const std::string& v): value(v) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const value_expr*>(other);
        return o != nullptr && value == o->value;
    }

    std::string value;
};

struct SINSP_PUBLIC list_expr: expr
{
    list_expr() { }

    explicit list_expr(const std::vector<std::string>& v): values(v) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const list_expr*>(other);
        return o != nullptr && values == o->values;
    }

    std::vector<std::string> values;
};

struct SINSP_PUBLIC unary_check_expr: expr
{
    unary_check_expr() { }

    unary_check_expr(
        const std::string& f,
        const std::string& a,
        const std::string& o): field(f), arg(a), op(o) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const unary_check_expr*>(other);
        return o != nullptr && field == o->field
            && arg == o->arg && op == o->op;
    }

    std::string field;
    std::string arg;
    std::string op;
};

struct SINSP_PUBLIC binary_check_expr: expr
{
    binary_check_expr() { }

    binary_check_expr(
        const std::string& f,
        const std::string& a,
        const std::string& o,
        expr* v): field(f), arg(a), op(o), value(v) { }

    ~binary_check_expr()
    {
        delete value;
    }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const binary_check_expr*>(other);
        return o != nullptr && field == o->field
            && arg == o->arg && op == o->op && value->is_equal(o->value);
    }

    std::string field;
    std::string arg;
    std::string op;
    expr* value;
};

/*!
	\brief Return a string representation of an AST.
	\return A string representation of an AST.
*/
std::string as_string(ast::expr &e);

/*!
	\brief Creates a deep clone of a filter AST
	\return The newly created cloned AST. Comparing the return value
    with the input parameter returns true
*/
expr* clone(expr* e);

}
}
}
