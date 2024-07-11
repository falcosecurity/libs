// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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
#include <memory>
#include <libsinsp/sinsp_public.h>

namespace libsinsp {
namespace filter {
namespace ast {

class expr;
struct and_expr;
struct or_expr;
struct not_expr;
struct identifier_expr;
struct value_expr;
struct list_expr;
struct unary_check_expr;
struct binary_check_expr;
struct field_expr;
struct field_transformer_expr;

/*!
    \brief A struct containing info about the position of the parser
    relatively to the string input. For example, this can either be used
    to retrieve context information when an exception is thrown.
*/
struct pos_info
{
    pos_info() = default;
    ~pos_info() = default;
    pos_info(uint32_t i, uint32_t l, uint32_t c): idx(i), line(l), col(c) { }
    pos_info(pos_info&&) = default;
    pos_info& operator = (pos_info&&) = default;
    pos_info(const pos_info&) = default;
    pos_info& operator = (const pos_info&) = default;
    bool operator ==(const pos_info &b) const
    {
        return idx == b.idx && line == b.line && col == b.col;
    }
    bool operator !=(const pos_info &b) const
    {
        return idx != b.idx || line != b.line || col != b.col;
    }

    inline void reset()
    {
        idx = 0;
        line = 1;
        col = 1;
    }

    inline std::string as_string() const
    {
        return "index " + std::to_string(idx)
            + ", line " + std::to_string(line)
            + ", column " + std::to_string(col);
    }

    uint32_t idx = 0;
    uint32_t line = 1;
    uint32_t col = 1;
};

static pos_info s_initial_pos;

/*!
    \brief Interface of AST visitors
*/
struct SINSP_PUBLIC expr_visitor
{
    virtual ~expr_visitor() = default;
    virtual void visit(and_expr*) = 0;
    virtual void visit(or_expr*) = 0;
    virtual void visit(not_expr*) = 0;
    virtual void visit(identifier_expr*) = 0;
    virtual void visit(value_expr*) = 0;
    virtual void visit(list_expr*) = 0;
    virtual void visit(unary_check_expr*) = 0;
    virtual void visit(binary_check_expr*) = 0;
    virtual void visit(field_expr*) = 0;
    virtual void visit(field_transformer_expr*) = 0;
};

/*!
    \brief an AST visitor that does not change the ast.
*/
struct SINSP_PUBLIC const_expr_visitor
{
    virtual ~const_expr_visitor() = default;
    virtual void visit(const and_expr*) = 0;
    virtual void visit(const or_expr*) = 0;
    virtual void visit(const not_expr*) = 0;
    virtual void visit(const identifier_expr*) = 0;
    virtual void visit(const value_expr*) = 0;
    virtual void visit(const list_expr*) = 0;
    virtual void visit(const unary_check_expr*) = 0;
    virtual void visit(const binary_check_expr*) = 0;
    virtual void visit(const field_expr*) = 0;
    virtual void visit(const field_transformer_expr*) = 0;
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
    virtual void visit(identifier_expr*) override;
    virtual void visit(value_expr*) override;
    virtual void visit(list_expr*) override;
    virtual void visit(unary_check_expr*) override;
    virtual void visit(binary_check_expr*) override;
    virtual void visit(field_expr*) override;
    virtual void visit(field_transformer_expr*) override;

private:
    bool m_should_stop_visit = false;
};

/*!
    \brief An analog of base_expr_visitor, but const.
*/
struct SINSP_PUBLIC const_base_expr_visitor: public const_expr_visitor
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

    virtual void visit(const and_expr*) override;
    virtual void visit(const or_expr*) override;
    virtual void visit(const not_expr*) override;
    virtual void visit(const identifier_expr*) override;
    virtual void visit(const value_expr*) override;
    virtual void visit(const list_expr*) override;
    virtual void visit(const unary_check_expr*) override;
    virtual void visit(const binary_check_expr*) override;
    virtual void visit(const field_expr*) override;
    virtual void visit(const field_transformer_expr*) override;

private:
    bool m_should_stop_visit = false;
};

/*!
    \brief A visitor that builds a string as it traverses the
    ast. Used to convert to strings.
*/
struct SINSP_PUBLIC string_visitor: public const_expr_visitor
{
public:
    virtual ~string_visitor() = default;
    virtual void visit(const and_expr*) override;
    virtual void visit(const or_expr*) override;
    virtual void visit(const not_expr*) override;
    virtual void visit(const identifier_expr*) override;
    virtual void visit(const value_expr*) override;
    virtual void visit(const list_expr*) override;
    virtual void visit(const unary_check_expr*) override;
    virtual void visit(const binary_check_expr*) override;
    virtual void visit(const field_expr*) override;
    virtual void visit(const field_transformer_expr*) override;

    const std::string& as_string();

protected:

    void visit_logical_op(const char *op, const std::vector<std::unique_ptr<expr>> &children);

    std::string m_str;
};

/*!
    \brief Base interface of AST hierarchy
*/
class SINSP_PUBLIC expr
{
public:
    virtual ~expr() = default;
    virtual void accept(expr_visitor*) = 0;
    virtual void accept(const_expr_visitor*) const = 0;
    virtual bool is_equal(const expr* other) const = 0;

    const pos_info& get_pos() const { return m_pos; }
    void set_pos(const pos_info& pos) { m_pos = pos; }

private:
    pos_info m_pos;
};

/*!
    \brief Compares two ASTs, returns true if they are deep equal
*/
static inline bool compare(const expr* left, const expr* right)
{
    return left->is_equal(right);
};

struct SINSP_PUBLIC and_expr: expr
{
    and_expr() = default;
    virtual ~and_expr() = default;

    explicit and_expr(std::vector<std::unique_ptr<expr>> &c): children(std::move(c)) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const and_expr*>(other);
        if (o == nullptr || o->children.size() != children.size())
        {
            return false;
        }

        for (size_t i = 0; i < children.size(); i++)
        {
            if (!compare(children[i].get(), o->children[i].get()))
            {
                return false;
            }
        }

        return true;
    }

    std::vector<std::unique_ptr<expr>> children;

    static std::unique_ptr<and_expr> create(std::vector<std::unique_ptr<expr>> &c,
                        const libsinsp::filter::ast::pos_info &pos = s_initial_pos)
    {
        auto ret = std::make_unique<and_expr>(c);
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC or_expr: expr
{
    or_expr() = default;
    virtual ~or_expr() = default;

    explicit or_expr(std::vector<std::unique_ptr<expr>> &c): children(std::move(c)) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const or_expr*>(other);
        if (o == nullptr || o->children.size() != children.size())
        {
            return false;
        }

        for (size_t i = 0; i < children.size(); i++)
        {
            if (!compare(children[i].get(), o->children[i].get()))
            {
                return false;
            }
        }

        return true;
    }

    std::vector<std::unique_ptr<expr>> children;

    static std::unique_ptr<or_expr> create(std::vector<std::unique_ptr<expr>> &c,
                       const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<or_expr>(c);
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC not_expr: expr
{
    not_expr() = default;
    virtual ~not_expr() = default;

    explicit not_expr(std::unique_ptr<expr> c): child(std::move(c)) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const not_expr*>(other);
        return o != nullptr && this->child->is_equal(o->child.get());
    }

    std::unique_ptr<expr> child;

    static std::unique_ptr<not_expr> create(std::unique_ptr<expr> c,
                        const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<not_expr>(std::move(c));
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC identifier_expr: expr
{
    identifier_expr() = default;
    virtual ~identifier_expr() = default;

    explicit identifier_expr(const std::string& i): identifier(i) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const identifier_expr*>(other);
        return o != nullptr && identifier == o->identifier;
    }

    std::string identifier;

    static std::unique_ptr<identifier_expr> create(const std::string& i,
                          const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<identifier_expr>(i);
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC value_expr: expr
{
    value_expr() = default;
    virtual ~value_expr() = default;

    explicit value_expr(const std::string& v): value(v) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const value_expr*>(other);
        return o != nullptr && value == o->value;
    }

    std::string value;

    static std::unique_ptr<value_expr> create(const std::string& v,
                          const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<value_expr>(v);
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC list_expr: expr
{
    list_expr() = default;
    virtual ~list_expr() = default;

    explicit list_expr(const std::vector<std::string>& v): values(v) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const list_expr*>(other);
        return o != nullptr && values == o->values;
    }

    std::vector<std::string> values;

    static std::unique_ptr<list_expr> create(const std::vector<std::string>& v,
                         const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<list_expr>(v);
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC unary_check_expr: expr
{
    unary_check_expr() = default;
    virtual ~unary_check_expr() = default;

    unary_check_expr(
        std::unique_ptr<expr> l,
        const std::string& o): left(std::move(l)), op(o) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const unary_check_expr*>(other);
        return o != nullptr && left->is_equal(o->left.get());
    }

    std::unique_ptr<expr> left;
    std::string op;

    static std::unique_ptr<unary_check_expr> create(
        std::unique_ptr<expr> l,
        const std::string& o,
        const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<unary_check_expr>(std::move(l), o);
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC binary_check_expr: expr
{
    binary_check_expr() = default;
    virtual ~binary_check_expr() = default;

    binary_check_expr(
        std::unique_ptr<expr> l,
        const std::string& o,
        std::unique_ptr<expr> r): left(std::move(l)), op(o), right(std::move(r)) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const binary_check_expr*>(other);
        return o != nullptr
            && left->is_equal(o->left.get())
	    && op == o->op
            && right->is_equal(o->right.get());
    }

    std::unique_ptr<expr> left;
    std::string op;
    std::unique_ptr<expr> right;

    static std::unique_ptr<binary_check_expr> create(
        std::unique_ptr<expr> l,
        const std::string& o,
        std::unique_ptr<expr> r,
        const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<binary_check_expr>(std::move(l), o, std::move(r));
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC field_expr: expr
{
    field_expr() = default;
    virtual ~field_expr() = default;

    field_expr(
        const std::string& f,
        const std::string& a): field(f), arg(a) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const field_expr*>(other);
        return o != nullptr && field == o->field && arg == o->arg;
    }

    std::string field;
    std::string arg;

    static std::unique_ptr<field_expr> create(
        const std::string& f,
        const std::string& a,
        const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<field_expr>(f, a);
        ret->set_pos(pos);
        return ret;
    }
};

struct SINSP_PUBLIC field_transformer_expr: expr
{
    field_transformer_expr() = default;
    virtual ~field_transformer_expr() = default;

    field_transformer_expr(
        const std::string& t,
        std::unique_ptr<expr> v): transformer(t), value(std::move(v)) { }

    void accept(expr_visitor* v) override
    {
        v->visit(this);
    };

    void accept(const_expr_visitor* v) const override
    {
        v->visit(this);
    };

    bool is_equal(const expr* other) const override
    {
        auto o = dynamic_cast<const field_transformer_expr*>(other);
        return o != nullptr && transformer == o->transformer && value->is_equal(o->value.get());
    }

    std::string transformer;
    std::unique_ptr<expr> value;

    static std::unique_ptr<field_transformer_expr> create(
        const std::string& m,
        std::unique_ptr<expr> v,
        const libsinsp::filter::ast::pos_info& pos = s_initial_pos)
    {
        auto ret = std::make_unique<field_transformer_expr>(m, std::move(v));
        ret->set_pos(pos);
        return ret;
    }
};

/*!
    \brief Return a string representation of an AST.
    \return A string representation of an AST.
*/
std::string as_string(const ast::expr *e);

/*!
    \brief Creates a deep clone of a filter AST
    \return The newly created cloned AST. Comparing the return value
    with the input parameter returns true
*/
std::unique_ptr<expr> clone(const expr* e);

}
}
}
