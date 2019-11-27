#!/usr/bin/python
import argparse
import json
import os
import re
import timeit

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.app.decompiler import DecompileOptions, DecompileException
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.util import DefinedDataIterator
from ghidra.util import UndefinedFunction
from ghidra.util.task import TaskMonitor


class ImportTableEnumerator:
    def __init__(self, verbose):
        self.symbol_table = currentProgram.getSymbolTable()
        self.verbose = verbose

    def crawl_it(self, api_dict):
        for external_symbol in self.symbol_table.getExternalSymbols():
            # getting the original imported name (it may be a mangled name of msvc exported C++ functions)
            external_data = external_symbol.getSymbolData3().split(",")

            if len(external_data) > 1 and external_data[1].startswith("?"):
                api_name = external_data[1]  # original msvc mangled name
            else:
                api_name = external_symbol.getName()  # normal name

            api_dll = external_symbol.getPath()[0].lower()
            if api_dll not in api_dict:
                api_dict[api_dll] = set()

            api_dict[api_dll].add(api_name)

            if self.verbose:
                print("    Import Table entry:   {}!{}".format(api_dll, api_name))


class StringParam:
    # regex for matching C string literals
    cast_regex = r"\*?[ \t]?(?:\(.+?\))?[ \t]?{}"
    string_regex = re.compile(cast_regex.format(r"L?\"(.+?)\""))
    var_regex = re.compile(cast_regex.format(r"([a-zA-Z_][a-zA-Z0-9_]*)"))

    def __init__(self, param):
        self.value = None
        self.name = None

        # Matching if param is a C string literal, i.e. "kernel32.dll" or L"MessageBoxW".
        str_match = StringParam.string_regex.match(param)
        if str_match:
            # It is a literal, storing the string value in self.value
            self.value = str_match.group(1)
        else:
            # It is not a string literal, hence it is a variable.
            # Checking if it is a simple variable (not considering eventual casts) or a more complex one (usually when
            # it is a part of a struct and hence param contains also the offset wrt. the struct object).
            var_match = StringParam.var_regex.match(param)
            self.name = var_match.group(1) if var_match else param

    def get_value(self):
        return self.value

    def get_name(self):
        return self.name

    def is_literal(self):
        return self.value is not None


class DynamicImportsEnumerator:
    # noinspection SpellCheckingInspection
    def __init__(self, verbose, api_db):
        self.verbose = verbose
        self.api_db_path = api_db if os.path.isfile(api_db) else None
        self.api_db = None

        symbol_table = currentProgram.getSymbolTable()

        gpa = symbol_table.getExternalSymbol("GetProcAddress")
        self.gpa_refs = gpa.getReferences() if gpa else []  # list of references (code or data) to GetProcAddress
        if len(self.gpa_refs) > 0 and self.gpa_refs[0].getReferenceType().isData():
            self.gpa_refs.extend(getReferencesTo(self.gpa_refs[0].getFromAddress()))

        # List of references (code or data) to LoadLibrary (and similar functions)
        ll_refs = []
        ll_symbols = ["LoadLibraryA", "LoadLibraryW",
                      "LoadLibraryExA", "LoadLibraryExW",
                      "GetModuleHandleA", "GetModuleHandleW"]
        for symbol in ll_symbols:
            ext_symbol = symbol_table.getExternalSymbol(symbol)
            if ext_symbol:
                ll_refs.extend(ext_symbol.getReferences())
        self.load_lib_functions = DynamicImportsEnumerator.__get_functions_containing_refs(ll_refs)

        # Regex for matching GetProcAddress arguments
        self.getprocaddress_regex = re.compile(r"GetProcAddress[ \t]?\("
                                               r"[ \t]?(.+?)[ \t]?,"  # 1st parameter (hModule)
                                               r"[ \t]?(?:\(.+?\))?[ \t]?(.+?)[ \t]?[),]")  # 2nd parameter (lpProcName)
        # Regex for matching LoadLibrary (et similia) first argument (i.e. the name of the dll)
        self.loadlibrary_regex = \
            r"{}\s?=\s?(?:LoadLibrary(?:Ex)?|GetModuleHandle)(?:[AW])?\s?\(\s?(?:\(.+?\))?\s?(.+?)\s?[),]"
        # Regex for handling wrong hmodule bug in Ghidra decompiler
        self.wrong_hmodule_regex = r"hModule(_[0-9]*)"
        # Regex for matching C function call and their arguments
        self.function_call_regex = r"{}[ \t]?\([ \t]?(.*)[ \t]?\)"
        # Regex for matching casts to HMODULE
        self.hmodule_cast_regex = r"(?:\*[ \t]?\([ \t]?HMODULE[ \t]?\*\))?\(?(?:\(.*\))?{}\)?"
        # Regex for matching variable alias assignments
        self.alias_regex = r"([a-zA-Z_][a-zA-Z0-9_]*)[ \t]?=[ \t]?(?:\(.+?\)\s*)?{}[ \t]*;"
        self.alias_regex2 = r"{}[ \t]?=[ \t]?([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*;"
        # Regex for matching internal functions
        self.internal_function_regex = r"((?:FUN|UndefinedFunction)\_[a-fA-F0-9]+)"
        self.internal_call_regex = re.compile(self.function_call_regex.format(self.internal_function_regex))
        # Regex for matching names of both internal functions and string/memory copy/move API functions
        self.call_regex = r"((?:FUN|UndefinedFunction)\_[a-fA-F0-9]+|" \
                          r"str(?:n)?cpy(?:_s)?|w?mem(?:cpy|move)(?:_s)?|basic_string<>)"
        self.call_regex = re.compile(self.function_call_regex.format(self.call_regex))

        # Initializing the decompiler
        self.flat_program = FlatProgramAPI(currentProgram)
        self.flat_decompiler = FlatDecompilerAPI(self.flat_program)
        decompiler_options = DecompileOptions()
        # Decompilation of some programs requires more memory than the default 50 MiB payload size.
        decompiler_options.setMaxPayloadMBytes(200)
        self.flat_decompiler.initialize()  # Explicit initialization is required for setting the options
        self.flat_decompiler.getDecompiler().setOptions(decompiler_options)
        self.decompiled_functions = {}

    def __update_api_dict(self, api_dict, api_dll, api_name):
        if api_dll is None:
            if self.api_db_path:
                if not self.api_db:  # api db not cached
                    with open(self.api_db_path, "r") as api_db_file:
                        self.api_db = json.load(api_db_file)

                if api_name in self.api_db:
                    # We must search which DLL the program is using for importing the API:
                    # to do so, we lookup if only one string in the executable corresponds to the name
                    # of one of the DLLs where api_name can be found!
                    dll_found = None
                    dll_count = 0
                    for dll in self.api_db[api_name]:
                        lower_dll = dll.lower()
                        for defined_str in DefinedDataIterator.definedStrings(currentProgram):
                            lower_str = defined_str.getValue().lower()
                            if lower_dll == lower_str or lower_dll == lower_str + ".dll":
                                dll_found = dll
                                dll_count += 1
                                break
                        # Note: we do not stop the outer loop: if we find more than one possible dll, we
                        #       cannot decide which one!
                    if dll_count == 1:
                        api_dll = dll_found

        if api_dll is not None:
            api_dll = api_dll.lower()

            if not api_dll.endswith(".dll") and not api_dll.endswith(".drv") and not api_dll.endswith(".ocx"):
                # LoadLibrary works also without specifying the .dll extension, but we need it
                # Note: winspool.drv is a kernel level DLL driver with a different extension
                api_dll += ".dll"

            if api_dll not in api_dict:
                api_dict[api_dll] = set()

            api_dict[api_dll].add(api_name)

            if self.verbose:
                print("    Found dynamic import: {}!{}".format(api_dll, api_name))
        elif self.verbose:
            print("    DLL not found for API:   {}".format(api_name))

    def __find_loadlibrary_assignment(self, h_module, code):
        # A common pattern in decompiled code of functions calling LoadLibrary is the following:
        #
        # local_var = LoadLibrary("comdlg32.dll");
        # ...
        # h_module = local_var; // h_module often is casted in the form *(HMODULE *)(h_module)
        #
        # So first we search for any assignment to h_module to find the name of local_var
        alias_matches = list(re.finditer(self.alias_regex2.format(h_module), code) or [])
        if len(alias_matches) > 0:
            # Found an alias assignment, so now the h_module variable we take into account is local_var
            # and we will search for the LoadLibrary assignment in the code above the alias assignment
            h_module = alias_matches[-1].group(1)
            code = code[:alias_matches[-1].start()]

        # Searching for a LoadLibrary call assigning the returned value to h_module (or its alias)
        loadlibrary_matches = re.findall(self.loadlibrary_regex.format(h_module), code)
        if len(loadlibrary_matches) > 0:
            # Found (at least) one direct assignment, getting the dll name parameter of the LoadLibrary call.
            # There may be multiple matches since the HMODULE variable can be reused for multiple
            # GetProcAddress calls, hence we use only the closest match (index -1) to the GetProcAddress call
            # we are analyzing.
            return StringParam(loadlibrary_matches[-1].strip())

    def __find_h_module_assignment(self, function, call_params, h_module, hmodule_offset):
        for index, call_param in enumerate(call_params):
            if h_module not in call_param and call_param not in h_module:
                continue

            # The call passes the hModule as a parameter, i.e. func2(hModule, ...)!

            # Decompiling the function
            function_code = self.__decompile_function(function)

            # Getting the name of the formal parameter corresponding to the hModule
            hmodule_param = self.__get_function_param(function, function_code, index)
            if not hmodule_param:
                break

            # Searching if there are any other aliases for the hModule parameter
            # e.g. void func( void* this, ... ) { /* ... */ local_var = this; /* ... */ }
            alias_match = re.search(self.alias_regex.format(hmodule_param), function_code)
            if alias_match:  # alias found, we search also assignment to it
                hmodule_param = r"(?:{}|{})".format(hmodule_param, alias_match.group(1))

            # Regex for searching casts to HMODULE of hmodule param (or of the alias), taking into account
            # an eventual offset inside the param (as found in the function calling GetProcAddress)
            # i.e. if previously we have found a call to GetProcAddress( *(HMODULE *)((int)this + 0x1c), ... )
            #      we search for assignment to a casted parameter at offset 0x1c.
            hmodule_assignment_regex = self.hmodule_cast_regex.format(
                r"(?:{}{}[^\)\n\r,]*)".format(hmodule_param, hmodule_offset))

            # Searching for direct assignments to the casted hModule
            # e.g. *(HMODULE *)((int)this + 0x1c) = LoadLibrary(...);
            lp_lib_filename = self.__find_loadlibrary_assignment(hmodule_assignment_regex, function_code)
            if lp_lib_filename:
                if not lp_lib_filename.is_literal():
                    # Note: in any case, if the parameter of the LoadLibrary call is not a string,
                    # lp_lib_filename will contain the name of the variable/parameter of the enclosing function
                    # that contains the string of the dll name
                    for param_index, param in self.__enumerate_function_params(function, function_code):
                        if param in lp_lib_filename.get_name():
                            return StringParam(call_params[param_index])
                else:
                    return lp_lib_filename
            else:
                break

    def __find_h_module(self, calling_function, call_context, function, h_module, offset):
        # We must find an assignment to the variable containing the hModule in order
        # to get the dll name parameter of LoadLibrary
        # First, we search for direct assignments to the hModule variable
        # i.e.   hModule = LoadLibrary("kernel32.dll");
        #        ...
        #        GetProcAddress(hModule, ...); <-- or a function calling GetProcAddress (i.e. the call we are analyzing)
        lp_lib_filename = self.__find_loadlibrary_assignment(re.escape(h_module), call_context)
        if not lp_lib_filename:
            # We didn't find any direct assignment, but maybe the hModule is passed to another function
            # (as a pointer) and it is assigned there!
            #
            # Example:
            # HMODULE hModule;
            # called_function(&hModule, ...); <-- call we are searching (note: same hModule passed to GetProcAddress)
            # ...
            # GetProcAddress(hModule, ...); <-- or a function calling GetProcAddress (i.e. the call we are analyzing)
            #
            # Hence, we search for all function calls above the one call we are analyzing.
            for called_function_name, call_params in self.__enumerate_internal_calls(call_context):
                # Avoiding to analyze again the function containing the GetProcAddress call: if we are
                # here, it means that that function does not contain the LoadLibrary call we are searching!
                if function and called_function_name == function.getName():
                    continue

                # Avoiding eventual recursive calls to calling_function, since it does not contain the LoadLibrary call
                # we are searching (otherwise lp_lib_filename would not be None and we would not be here!)
                if called_function_name == calling_function.getName():
                    continue

                # Getting the list of function objects corresponding to the called function name
                called_functions = getGlobalFunctions(called_function_name)
                if len(called_functions) == 0:
                    continue

                # Avoiding to analyze functions not containing calls to LoadLibrary and similar functions
                if called_functions[0] not in self.load_lib_functions:
                    continue

                # Searching for an assignment to the formal parameter corresponding to the hModule passed to the call
                # i.e.
                # called_function(&hModule, ...); <- call we have found in calling_function
                # ...
                # void called_function(HMODULE* param1, ...) {
                #     ...
                #     *param1 = LoadLibrary(...); <- call to LoadLibrary we are searching
                #     ...
                # }
                lp_lib_filename = self.__find_h_module_assignment(called_functions[0], call_params, h_module, offset)

                if lp_lib_filename:  # Assignment found, no need to continue the loop!
                    break
        return lp_lib_filename

    def __enumerate_call_params(self, function, external_params):
        function_regex = self.__get_function_regex(function.getName())

        # Searching the values of the missing parameters in all the functions that call function
        for calling_function in self.__get_calling_functions(function):
            # Getting the decompiled code of calling_function
            calling_function_code = self.__decompile_function(calling_function)

            # For each call to function we find in calling_function...
            for function_call in function_regex.finditer(calling_function_code):
                # The actual parameters passed to the call
                function_call_params = [x.strip() for x in function_call.group(1).split(',')]

                lp_proc_name = None
                lp_lib_filename = None

                if "lpProcName" in external_params and external_params["lpProcName"] < len(function_call_params):
                    lp_proc_name = StringParam(function_call_params[external_params["lpProcName"]])

                if "lpLibFileName" in external_params and external_params["lpLibFileName"] < len(function_call_params):
                    lp_lib_filename = StringParam(function_call_params[external_params["lpLibFileName"]])
                    if not lp_lib_filename.is_literal():
                        call_context = calling_function_code[:function_call.start()]
                        assignment_matches = re.findall(r"{}[ \t]?=[ \t]?(.*?);".format(lp_lib_filename.get_name()),
                                                        call_context)
                        if len(assignment_matches) > 0:
                            lp_lib_filename = StringParam(assignment_matches[-1])
                        else:
                            for called_function_name, params in self.__enumerate_function_calls(call_context):
                                if called_function_name == function.getName():
                                    continue

                                if called_function_name == calling_function.getName():  # recursion?
                                    continue

                                dll_name = self.__find_string_literal_param(params, lp_lib_filename.get_name())
                                if dll_name:
                                    lp_lib_filename = dll_name
                                    break

                if "hModule" in external_params:
                    # decompiled code before the call to func, i.e. the function containing the GetProcAddress call
                    call_context = calling_function_code[:function_call.start()]

                    # hModule is passed as a parameter of the function calling GetProcAddress (func)
                    h_module_index = external_params["hModule"]["index"]
                    offset = external_params["hModule"]["offset"]

                    # variable containing the hModule value and passed to func by calling_func
                    h_module = function_call_params[h_module_index]

                    lp_lib_filename = self.__find_h_module(calling_function, call_context, function, h_module, offset)

                yield lp_lib_filename, lp_proc_name

    def __parse_api_params(self, function, function_code, getprocaddress_call):
        api_dll = None
        api_name = None

        # there is no need to match against the full decompiled function:
        # the HMODULE variable, in fact, must be defined before the GetProcAddress call!
        call_context_code = function_code[:getprocaddress_call.start()]

        # 1st param of GetProcAddress, i.e. the variable containing the return value of LoadLibrary et similia.
        h_module = getprocaddress_call.group(1).strip()

        # searching for any possible assignment to the HMODULE variable used by GetProcAddress
        lp_lib_filename = self.__find_h_module(function, call_context_code, None, h_module, "")
        if not lp_lib_filename:
            for called_function_name, params in self.__enumerate_function_calls(call_context_code):
                if called_function_name == function.getName():
                    continue

                dll_string = DynamicImportsEnumerator.__find_string_literal_param(params, h_module)
                if dll_string and dll_string.is_literal():
                    api_dll = dll_string.get_value()
                    break
        elif lp_lib_filename.is_literal():
            # assignment found and the parameter of LoadLibrary is a C string literal!
            api_dll = lp_lib_filename.get_value()  # the dll name parameter of the LoadLibrary call

        # 2nd param of GetProcAddress, i.e. the API function name (C string) or a variable pointing to it.
        lp_proc_name = StringParam(getprocaddress_call.group(2).strip())
        if lp_proc_name.is_literal():  # the 2nd argument of GetProcAddress is a C string literal
            api_name = lp_proc_name.get_value()
        else:
            for called_function_name, params in self.__enumerate_function_calls(call_context_code):
                if re.match(self.internal_function_regex, called_function_name):
                    continue

                if called_function_name == function.getName():
                    continue

                api_string = DynamicImportsEnumerator.__find_string_literal_param(params, lp_proc_name.get_name())
                if api_string and api_string.is_literal():
                    api_name = api_string.get_value()
                    break

        if api_dll is not None and api_name is not None:  # found both dll and name of the API used!
            return api_dll, api_name, None

        # There are missing parameters: checking if they are arguments of the enclosing function
        external_params = {}
        for index, param_name in self.__enumerate_function_params(function, call_context_code):
            if api_dll is None:
                # could not find the dll of the API
                if lp_lib_filename:
                    # a LoadLibrary call was found but its parameter is not a C string literal
                    # (otherwise api_dll would not be None)
                    if param_name == lp_lib_filename.get_name():
                        # the parameter of LoadLibrary is also a formal parameter of the enclosing function
                        external_params["lpLibFileName"] = index
                        continue
                elif param_name in h_module:
                    # no LoadLibrary call was found but the hModule used by GetProcAddress is passed as an
                    # argument of the enclosing function!

                    # Note: hModule may be at offset wrt. the param, e.g. (int)this + 0x1c where 'this' is the name
                    # of the parameter, hence we use the 'in' operator in the elif condition!
                    hmodule_match = re.match(self.hmodule_cast_regex.format(r"(.[^\)\n\r,]*)"), h_module)
                    if hmodule_match:  # hModule is a parameter of the enclosing function!
                        external_params["hModule"] = dict()
                        external_params["hModule"]["index"] = index
                        external_params["hModule"]["offset"] = re.escape(hmodule_match.group(1).replace(param_name, ""))
                    continue

            if api_name is None and param_name == lp_proc_name.get_name():
                # 2nd argument of GetProcAddress is not a C string constant
                # but it is a formal parameter of the enclosing function!
                external_params["lpProcName"] = index
                continue

        '''if api_dll is None and "hModule" not in external_params:
            print("hModule var: {}".format(h_module))
            for called_function, call_params in self.__enumerate_internal_calls(call_context_code):
                if called_function.getName() == function.getName():
                    continue

                # Avoiding to analyze functions not containing calls to LoadLibrary and similar functions
                if called_function not in self.load_lib_functions:
                    continue

                print(" - call to {} with params {}".format(called_function.getName(), call_params))

                lp_lib_filename = self.__find_h_module_assignment(called_function, call_params, h_module, "")

                if lp_lib_filename is not None:
                    break'''

        return api_dll, api_name, external_params

    def __fix_calling_conventions(self):
        # if a function contains a variable declared as void* this,
        # it means that its original calling convention was __thiscall!
        this_var_regex = re.compile(r"(?:void|int)\s?\*\s?this\s?;")

        # often Ghidra assigns the HMODULE value to an uninitialized int variable!
        # this regex searches code like the following:
        # int local_30;
        # ...  // <-- no assignment to local_30!
        # *(HMODULE *)(local_30 + 0x1c) = pHVar1;
        local_var_regex = re.compile(r'(?:void\s?\*\s?|int\s+)((?!unaff|extraout)[a-zA-Z][a-zA-Z0-9_]+);'
                                     r'(.*?)'  # code between void*/int var. decl. and the corresponding HMODULE cast
                                     r'(?:\*\s?\(\s?HMODULE\s?\*\))\s?\(?(?:\([^\n]+\))?\1(?:[^)\n\r,]+)\)?', re.DOTALL)

        # At the moment we consider only functions containing calls to LoadLibrary and similar functions
        for ll_function in self.load_lib_functions:
            if ll_function.getCallingConventionName() == "__thiscall":  # function is already __thiscall
                continue

            try:
                ll_function_code = self.flat_decompiler.decompile(ll_function)
            except DecompileException:
                continue

            if this_var_regex.search(ll_function_code):
                if self.verbose:
                    print("    Changed calling convention of {}".format(ll_function.getName()))
                ll_function.setCallingConvention("__thiscall")
            else:
                # Note: matching using a single regex is theoretically possible, but Jython gives stack overflow!
                # Hence we need to use a second regex for searching assignments to the int variable found by the
                # first one in the code between the declaration and the cast: if no assignment is found, the function
                # was a __thiscall!
                # See https://regex101.com/r/zjdu3C/2/ for the single regex version.
                var_match = local_var_regex.search(ll_function_code)
                if var_match and not re.search(r"{}\s?=\s?.+?;".format(var_match.group(1)), var_match.group(2)):
                    if self.verbose:
                        print("    Changed calling convention of {}".format(ll_function.getName()))
                    ll_function.setCallingConvention("__thiscall")

    def crawl_dynamic_imports(self, api_dict):
        if currentProgram.getLanguage().getDefaultSpace().getSize() == 32:
            # Sometimes on x86 Ghidra is wrong about the calling convention of functions...
            self.__fix_calling_conventions()

        # getting all functions containing call references to GetProcAddress
        dyn_imp_functions = DynamicImportsEnumerator.__get_functions_containing_refs(self.gpa_refs)

        # for each function containing (at least) a call to GetProcAddress...
        for function in dyn_imp_functions:
            function_code = self.__decompile_function(function)  # get the decompiled C code of the function.

            # for each call to GetProcAddress we find inside the decompiled function (it may call it multiple times!)...
            for getprocaddress_call in self.getprocaddress_regex.finditer(function_code):
                # getting the directly available parameters of the call to GetProcAddress and of the related call to
                # LoadLibrary, as well as the external parameters (i.e. those that are not as C string literals but
                # instead are referencing the parameters of the enclosing function).
                api_dll, api_name, ext_params = self.__parse_api_params(function, function_code, getprocaddress_call)

                # Note: ext_params == None => both api_dll and api_name are not None, i.e. we have
                # found everything we needed about the call to WinAPI!
                if ext_params is None:
                    self.__update_api_dict(api_dict, api_dll, api_name)
                    continue

                # Note: ext_params == {} => no external parameters found, but some parameters of the call are missing.
                if len(ext_params) == 0:
                    if api_name is not None:
                        # Here, if api_name != None => api_dll == None (otherwise ext_params would have been None).
                        # Note: we can find the DLL in other ways, e.g. db of APIs.
                        self.__update_api_dict(api_dict, api_dll, api_name)
                    continue

                # some of the params of GetProcAddress (or LoadLibrary) are not directly available but are
                # parameters of the enclosing function.

                # for each pair of actual parameters used in the calls to the enclosing function
                # e.g.
                # function(var, "GetFileTime"); <- lp_proc_name == "GetFileTime"
                #
                # e.g.
                # other_function(hModule, "user32.dll"); <- other function which calls LoadLibrary
                # ...
                # function(hModule, "MessageBoxA"); <- lp_lib_filename == "user32.dll" and lp_proc_name == "MessageBoxA"
                for lp_lib_filename, lp_proc_name in self.__enumerate_call_params(function, ext_params):
                    if lp_lib_filename and lp_lib_filename.is_literal():
                        # the name of the dll was found
                        api_dll = lp_lib_filename.get_value()

                    if lp_proc_name and lp_proc_name.is_literal():
                        # the name of the api was found
                        api_name = lp_proc_name.get_value()

                    if api_name:
                        self.__update_api_dict(api_dict, api_dll, api_name)

    def __decompile_function(self, function):
        function_name = function.getName()
        if function_name not in self.decompiled_functions:
            # the function was never decompiled (not in cache)
            self.decompiled_functions[function_name] = {}
            try:
                code = self.flat_decompiler.decompile(function)
            except DecompileException:
                # If the decompiler fails, set the code as signature + dummy function body
                code = function.getSignature().getPrototypeString() + "{}"

            for ref in re.finditer(r"([a-zA-Z_][a-zA-Z0-9_]*)[ \t]?=[ \t]?(?:\(.+?\)[ \t]?)?"
                                   r"((?:LoadLibrary(?:Ex)?|GetModuleHandle)(?:[AW])?|GetProcAddress)_exref;", code):
                code = re.sub(r"(?:\(HMODULE\))?[ \t]?"
                              r"(?:\([ \t]?\*)?[ \t]?\(code \*\)[ \t]?(?:\([ \t]?\*)?[ \t]?{}\)".format(ref.group(1)),
                              ref.group(2), code)

            self.decompiled_functions[function_name]["code"] = code

        # returning the (cached) decompiled code of function
        return self.decompiled_functions[function_name]["code"]

    def __get_function_regex(self, function_name):
        if "regex" not in self.decompiled_functions[function_name]:
            self.decompiled_functions[function_name]["regex"] = \
                re.compile(self.function_call_regex.format(function_name))
        return self.decompiled_functions[function_name]["regex"]

    def __get_function_param(self, function, function_code, index):
        if index < function.getParameterCount():
            return function.getParameter(index).getName()
        else:
            # Sometimes Ghidra is wrong: getParameterCount() returns 0 but the decompiled code has parameters!
            # So, in any case, if the index is greater than or equal to the parameters count (which may be wrong), we
            # try to get the parameters from the decompiled code of the function

            function_name = function.getName()
            if "params" not in self.decompiled_functions[function_name]:
                # Getting the parameters from the function signature in its decompiled code
                params_match = self.__get_function_regex(function_name).search(function_code)
                # Storing the parameters array in cache so that if we need them another time we do not need to use the
                # regex search again!
                self.decompiled_functions[function_name]["params"] = params_match.group(1).split(',')

            params = self.decompiled_functions[function_name]["params"]
            return params[index].strip() if index < len(params) else None

    def __enumerate_function_params(self, function, function_code):
        if function.getParameterCount() > 0:
            for param in function.getParameters():
                yield (param.getOrdinal(), param.getName())
        else:
            function_name = function.getName()
            # sometimes Ghidra is wrong: getParameterCount() returns 0 but the decompiled code has parameters!
            if "params" not in self.decompiled_functions[function_name]:
                params_match = self.__get_function_regex(function_name).search(function_code)
                self.decompiled_functions[function_name]["params"] = params_match.group(1).split(',')

            params = self.decompiled_functions[function_name]["params"]

            for index, name in enumerate(params):
                # Note: name is in the format '<type> <param_name>', so we rsplit wrt the space and take the last
                # token, which is the name of the parameter
                yield (index, name.rsplit(" ", 1)[-1].replace("*", "").strip())

    def __enumerate_internal_calls(self, code):
        return DynamicImportsEnumerator.__enumerate_calls(code, self.internal_call_regex)

    def __enumerate_function_calls(self, code):
        return DynamicImportsEnumerator.__enumerate_calls(code, self.call_regex)

    @staticmethod
    def __find_string_literal_param(params, var):
        var_found = False
        str_param = None
        for param in params:
            if var in param:
                var_found = True
            else:
                str_param = StringParam(param)

            if var_found and str_param and str_param.is_literal():
                return str_param

    @staticmethod
    def __get_functions_containing_refs(refs):
        callers = set()
        for reference in refs:
            # considering only call/jump references
            reference_type = reference.getReferenceType()
            if not reference_type.isCall() and not reference_type.isJump() and not reference_type.isIndirect():
                continue

            # getting the origin address of the call...
            call_address = reference.getFromAddress()
            # ...and the function containing that call
            calling_function = getFunctionContaining(call_address)
            if not calling_function:
                # no normal function contains the address, however it may be contained in an UndefinedFunction
                calling_function = UndefinedFunction.findFunction(currentProgram, call_address, TaskMonitor.DUMMY)

            if calling_function:
                # a calling function was found
                callers.add(calling_function)
        return callers  # returning the set of functions that has call references in refs

    @staticmethod
    def __get_calling_functions(function):
        # Note: returning function.getCallingFunctions(TaskMonitor.DUMMY) would not consider UndefinedFunctions!

        # getting the symbols corresponding to the given function
        function_symbols = getSymbols(function.getName(), None)

        if len(function_symbols) == 0:
            return []

        # getting all the references to the symbol corresponding to the given function
        refs_to_function = function_symbols[0].getReferences()
        # returning all the functions (undefined ord not) that call function
        return DynamicImportsEnumerator.__get_functions_containing_refs(refs_to_function)

    @staticmethod
    def __enumerate_calls(code, regex):
        calls_matches = regex.findall(code)
        for i in range(1, len(calls_matches) + 1):
            # searching matches backward, so that we first analyze function calls close to the one containing the
            # call to GetProcAddress and currently being analyzed.
            yield calls_matches[-i][0].strip(), calls_matches[-i][1].split(",")


def get_api_dict(imp_types, verbose, api_db):
    api_dict = {}

    print "Analyzing imports of {}... ".format(currentProgram.getName()),
    if verbose:
        print("")  # in verbose mode we will list all the API found, so a new line is required!

    start_time = timeit.default_timer()

    if imp_types != "dynamic":  # imp_types is "all" or "it"
        api_dict["it"] = {}
        it_enumerator = ImportTableEnumerator(verbose)
        it_enumerator.crawl_it(api_dict["it"])

    if imp_types != "it":  # imp_types is "all" or "dynamic"
        api_dict["dynamic"] = {}
        dyn_enumerator = DynamicImportsEnumerator(verbose, api_db)
        dyn_enumerator.crawl_dynamic_imports(api_dict["dynamic"])

    elapsed = timeit.default_timer() - start_time

    if verbose:
        print("Analysis Completed!")
    else:
        print("COMPLETED.")

    print("Elapsed time: {} seconds".format(elapsed))

    return api_dict


def test_api_dict(api_dict):
    test_dict = {
        "kernel32.dll": {"GetShortPathNameA", "GetComputerNameA", "GetCurrentProcessId", "GetCurrentThreadId",
                         "GetDiskFreeSpaceExA", "GetLogicalDrives"},
        "shell32.dll": {"ShellAboutA", "IsUserAnAdmin"},
        "user32.dll": {"MessageBoxA"},  # , "MessageBoxExA"},
        "advapi32.dll": {"GetUserNameA"},
        "shlwapi.dll": {"StrToIntA"}
    }
    test_res = True
    for test_key in test_dict:
        if test_key not in api_dict:
            test_res = False
            print("Missing DLL {} from the results!".format(test_key))
        else:
            diff = test_dict[test_key].difference(api_dict[test_key])
            if len(diff) > 0:
                test_res = False
            for missing_api in diff:
                print("Missing API {} from the results!".format(missing_api))
    return test_res


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghidra script for crawling the APIs used by the analyzed executable",
                                     prefix_chars='/')
    parser.add_argument("imports_types", choices=['all', 'it', 'dynamic'])
    parser.add_argument("/log", default=None, nargs="?", const="{}/logs".format(os.getcwd()))
    parser.add_argument("/apidb")
    parser.add_argument("/v", dest="verbose", action="store_true", default=False)
    args = parser.parse_args(getScriptArgs())

    # import profile
    # profiler = profile.Profile()
    # result = profiler.runcall(get_api_dict, args.imports_types, args.verbose)
    result = get_api_dict(args.imports_types, args.verbose, args.apidb)

    if "dynimp" in currentProgram.getName():
        print("Test passed! :)" if test_api_dict(result["dynamic"]) else "Test failed! :(")

    if args.log:
        if args.verbose:
            print "Saving log file... ",
        if not os.path.exists(args.log):
            os.makedirs(args.log)
        file_path = os.path.join(args.log, '{}.json'.format(currentProgram.getExecutableMD5()))
        with open(file_path, 'w') as fp:
            json.dump(result, fp, cls=SetEncoder, indent=4)
        if args.verbose:
            print("DONE.")

    # profiler.print_stats("time")
