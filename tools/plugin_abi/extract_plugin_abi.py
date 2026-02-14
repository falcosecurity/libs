#!/usr/bin/env python

# pahole -aA -C plugin_api build/local/libsinsp/libsinsp.a 2>/dev/null | python tools/plugin_abi/extract_plugin_abi.py 3 > userspace/plugin/plugin_abi.h

import argparse
import sys

import pyparsing as pp

pp.ParserElement.enablePackrat()


def make_parser():
    comment = pp.cStyleComment | pp.cppStyleComment
    ident = pp.Word(pp.alphas + '_', pp.alphanums + '_')
    typedef_kw = pp.Keyword('typedef')
    struct_kw = pp.Keyword('struct')

    ty = pp.Forward()
    ty_qualifier = pp.oneOf('const volatile signed unsigned short long *')
    ty_qualifiers = pp.ZeroOrMore(ty_qualifier)
    basic_ty = ty_qualifiers + ident('type') + ty_qualifiers
    fptr_ty = basic_ty('return_type') + pp.Suppress('(') + pp.Suppress('*') + ident('name') + pp.Suppress(
        ')') + pp.Suppress('(') + pp.Optional(
        pp.delimitedList(ty)) + pp.Suppress(')')
    ty <<= basic_ty | fptr_ty

    field_decl = pp.Forward()
    simple_field = basic_ty('type') + ident('name') + pp.Suppress(';') + pp.Optional(comment('field_comment'))
    fptr_field = basic_ty('return_type') + pp.Suppress('(') + pp.Suppress('*') + ident('name') + pp.Suppress(
        ')') + pp.Suppress('(') + pp.Optional(
        pp.Group(pp.delimitedList(ty)))('args') + pp.Suppress(')') + pp.Suppress(';') + pp.Optional(
        comment('field_comment'))
    field_decl <<= pp.Group(simple_field | fptr_field)

    struct_decl = pp.Forward()
    member_decl = field_decl('field') | struct_decl('nested') | pp.Suppress(comment)

    struct_decl <<= (
            pp.Suppress(pp.Optional(typedef_kw)) +
            pp.Suppress(struct_kw) +
            pp.Suppress(pp.Optional(ident('struct_tag'))) +
            pp.Suppress('{') +
            pp.OneOrMore(member_decl)('fields') +
            pp.Suppress('}') +
            pp.Suppress(pp.Optional(ident('name'))) +
            pp.Suppress(';')
    )

    return struct_decl


def make_comment_parser():
    number = pp.Word(pp.nums)
    return pp.Suppress('/*') + number('offset') + number('size') + pp.Suppress('*/')


def gen_static_asserts(struct_definition, abi_version):
    parser = make_parser()
    comment_parser = make_comment_parser()
    result = parser.parseString(struct_definition)
    print('#ifndef PLUGIN_ABI_VERSION')
    print('#define PLUGIN_ABI_VERSION {}'.format(abi_version))
    print('#if defined(__linux__) && defined(__x86_64__) && (defined(__GNUC__) || (__STDC_VERSION__ >= 201112L))')
    print('#include <assert.h>')
    print('#include <stddef.h>')
    for field in result.fields:
        layout = comment_parser.parseString(field.field_comment)
        # sizeof(((type *)0)->member)
        print('static_assert(sizeof(((plugin_api*)0)->{}) == {}, "{} size mismatch");'.format(field.name, layout.size,
                                                                                              field.name))
        print('static_assert(offsetof(plugin_api, {}) == {}, "{} offset mismatch");'.format(field.name, layout.offset,
                                                                                            field.name))
    print('#endif')
    print('#endif')
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate static asserts for plugin ABI')
    parser.add_argument('abi_version', type=int, help='ABI version')

    args = parser.parse_args()
    gen_static_asserts(sys.stdin.read(), args.abi_version)
