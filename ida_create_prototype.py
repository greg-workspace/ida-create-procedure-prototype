import ida_typeinf
import idaapi

get_struct = lambda name: idaapi.get_struct(idaapi.get_struct_id(name))
def get_struct(name):
        sid = idaapi.get_struc_id(name)
        return idaapi.get_struc(sid)

def enum_members(struc):
        idx = 0
        while idx != -1:
                member = struc.get_member(idx)
                yield member
                idx = idaapi.get_next_member_idx(struc,member.soff)

def set_member_type_info(struc,member,decl):
        ti = idaapi.tinfo_t()
        idaapi.parse_decl2(None,decl,ti,0)
        idaapi.set_member_tinfo(struc,member,0,ti,0)

def type_for_name(name):
        ret = ida_typeinf.get_named_type(None, name, 0)
        if not ret:
                return None
        type_str = ret[1]
        field_str = ret[2]
        t = ida_typeinf.tinfo_t()
        t.deserialize(None, type_str, field_str)
        typeinfo = str(t)
        
        typeinfo = typeinfo.replace("__stdcall","(__stdcall*)")
        #print 'procdure type:', typeinfo
        return typeinfo


def set_struct_function_type(struct_name):
        struct =  get_struct(struct_name)
        for m in enum_members(struct):
                name = idaapi.get_member_name(m.id)
                typeinfo = type_for_name(name)
                if typeinfo:
                        print typeinfo
                        set_member_type_info(struct, m, typeinfo +";")            
print '-'*80      
"""
Prepare local type as follows

struct struct_apis
{
    _QWORD GetProcAddress;
    _QWORD LoadLibraryW;
    _QWORD LoadLibraryA;
    _QWORD CreateProcessA;
    _QWORD CreateProcessW;
};
"""
set_struct_function_type('struct_apis')

"""
struct __declspec(align(8)) struct_apis
{
  FARPROC (__stdcall *GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
  HMODULE (__stdcall *LoadLibraryW)(LPCWSTR lpLibFileName);
  HMODULE (__stdcall *LoadLibraryA)(LPCSTR lpLibFileName);
  BOOL (__stdcall *CreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
  BOOL (__stdcall *CreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
};


"""


print "="*80