# Author: Arquimedes Canedo
import glob
import pdb

import multiprocessing
import numpy as np
import pickle


import clang.cindex
clang.cindex.Config.set_library_path('/Library/Developer/CommandLineTools/usr/lib/')



def dump_code(code, cppfile='/tmp/tempfile.cpp'):
    with open(cppfile, 'w') as f:
        f.write(code)
    return cppfile

def get_annotations(node):
    return [c.displayname for c in node.get_children()
            if c.kind == clang.cindex.CursorKind.ANNOTATE_ATTR]

def clang_find_functions(code):
    cppfile = dump_code(code)
    index = clang.cindex.Index.create()
    tu = index.parse(cppfile, ['-E', '-x', 'c++'])
    objects = {"functions": [], "enums": [], "namespaces": [], "classes": [], "structs": []}
    traverse(tu.cursor, cppfile, objects)
    return objects['functions']

def traverse(c, path, objects):
    if c.location.file and not c.location.file.name.endswith(path):
        return

    if c.spelling == "PARULA_COLOR_MAP": # Fix to prevent python stack overflow from infinite recursion
        return

#    print(c.kind, c.spelling)

    if c.kind == clang.cindex.CursorKind.TRANSLATION_UNIT or c.kind == clang.cindex.CursorKind.UNEXPOSED_DECL:
        # Ignore  other cursor kinds
        pass

    elif c.kind == clang.cindex.CursorKind.NAMESPACE:
        objects["namespaces"].append(c.spelling)
        #print("Namespace", c.spelling, c.get_children())
        pass

    elif c.kind == clang.cindex.CursorKind.FUNCTION_TEMPLATE:
        #print("Function Template", c.spelling, c.raw_comment)
        objects["functions"].append(Function(c))
        return

    elif c.kind == clang.cindex.CursorKind.FUNCTION_DECL:
        #print("FUNCTION_DECL", c.spelling, c.raw_comment)
        objects["functions"].append(Function(c))
        return

    elif c.kind == clang.cindex.CursorKind.ENUM_DECL:
        #print("ENUM_DECL", c.spelling, c.raw_comment)
        objects["enums"].append(Enum(c))
        return

    elif c.kind == clang.cindex.CursorKind.CLASS_DECL:
        #print("CLASS_DECL", c.spelling, c.raw_comment)
        objects["classes"].append(Class(c))
        return

    elif c.kind == clang.cindex.CursorKind.CLASS_TEMPLATE:
        #print("CLASS_TEMPLATE", c.spelling, c.raw_comment)
        objects["classes"].append(Class(c))
        return

    elif c.kind == clang.cindex.CursorKind.STRUCT_DECL:
        #print("STRUCT_DECL", c.spelling, c.raw_comment)
        objects["structs"].append(Class(c))
        return

    else:
        #print("Unknown", c.kind, c.spelling)
        pass

    for child_node in c.get_children():
        traverse(child_node, path, objects)

class Function(object):
    def __init__(self, cursor):
        self.name = cursor.spelling
        self.annotations = get_annotations(cursor)
        self.access = cursor.access_specifier
        self.extent = cursor.extent
        self.extent = {'start_line':cursor.extent.start.line, 'start_column':cursor.extent.start.column,
                'end_line':cursor.extent.end.line, 'end_column':cursor.extent.end.column}
        parameter_dec = [c for c in cursor.get_children() if c.kind == clang.cindex.CursorKind.PARM_DECL]
        
        parameters = []
        for p in parameter_dec:
            children = []
            for c in p.get_children():
                children.append(c.spelling)
            parameters.append((p.spelling, p.type.spelling, children))

        self.parameters = parameters
        self.documentation = cursor.raw_comment


class Enum(object):
    def __init__(self, cursor):
        self.name = cursor.spelling
        self.constants = [c.spelling for c in cursor.get_children() if c.kind ==
                       clang.cindex.CursorKind.ENUM_CONSTANT_DECL]
        self.documentation = cursor.raw_comment

class Class(object):
    def __init__(self, cursor):
        self.name = cursor.spelling
        self.annotations = get_annotations(cursor)

if __name__ == '__main__':
    corpus = []
    labels = []
    for f in glob.glob('./**/*.c', recursive=True):
        # errors='replace' gets rid of the unicode problems 
        # https://stackoverflow.com/questions/35028683/python3-unicodedecodeerror-with-readlines-method
        with open(f, 'r', errors='replace') as fd:
            try:
                content = fd.read().splitlines()
                code = '\n'.join(content)
            except: 
                print('%s unicode problem' % (f))

        found_functions = clang_find_functions(code)
        for func in found_functions:
            start_line = func.extent['start_line']
            end_line = func.extent['end_line']
            if start_line == end_line:
                continue
            else:
                corpus.append('\n'.join(content[start_line-1:end_line]))


    for i, code in enumerate(corpus):
        with open('/tmp/'+str(i)+'.c', 'w') as fd:
            fd.write(code)

    print('Preprocessed a total of %s functions' % (len(corpus)))