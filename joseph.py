import idaapi
import idautils

GLB_PluginName = "Insn Colorizer"
GLB_HotKey = ""

try:
    hook_place = _idaapi
except:
    import _ida_idp
    hook_place = _ida_idp


JUMP_FLAGS = [idaapi.fl_JF, idaapi.fl_JN]
FLOW_FLAGS = [idaapi.fl_JF, idaapi.fl_JN,  idaapi.fl_F]

def is_split_jmp(ea):
    xrefs = [an_xref for an_xref in idautils.XrefsFrom(ea) if an_xref.type in FLOW_FLAGS]
    if len(xrefs) == 0:
        return False
    if len(xrefs) > 1:
        return True
    return False

def is_jmp(ea):
    xrefs = [an_xref for an_xref in idautils.XrefsFrom(ea) if an_xref.type in JUMP_FLAGS]
    if len(xrefs) > 0:
        return True
    return False 

INSN_RULES = [
    (idaapi.is_call_insn, idaapi.SCOLOR_REGCMT),
    (idaapi.is_ret_insn, idaapi.SCOLOR_REGCMT),
    (is_split_jmp, idaapi.SCOLOR_DREF),
    (is_jmp, idaapi.SCOLOR_REGCMT),
]

"""
idaapi.SCOLOR_REGCMT  - Blue
idaapi.SCOLOR_INSN    - Dark blue
idaapi.SCOLOR_DREF     - Sky blue
idaapi.SCOLOR_RPTCMT  - Grey
idaapi.SCOLOR_CHAR    - Green
idaapi.SCOLOR_DREFTAIL - Army green
idaapi.SCOLOR_STRING  - Light Green
idaapi.SCOLOR_VOIDOP   - Orange
idaapi.SCOLOR_CREFTAIL - Red
idaapi.SCOLOR_ERROR    - Black on red background
idaapi.SCOLOR_MACRO   - Purple
idaapi.SCOLOR_DEFAULT - Blue
idaapi.SCOLOR_AUTOCMT - Grey
idaapi.SCOLOR_INSN    - Dark blue
idaapi.SCOLOR_DATNAME - Dark blue
idaapi.SCOLOR_DNAME   - Blue
idaapi.SCOLOR_DEMNAME - Blue
idaapi.SCOLOR_SYMBOL  - Dark blue
idaapi.SCOLOR_CHAR    - Green
idaapi.SCOLOR_STRING  - Light Green
idaapi.SCOLOR_NUMBER  - Green
idaapi.SCOLOR_VOIDOP   - Orange
idaapi.SCOLOR_CREF     - Green
idaapi.SCOLOR_DREF     - Sky blue
idaapi.SCOLOR_CREFTAIL - Red
idaapi.SCOLOR_DREFTAIL - Army green
idaapi.SCOLOR_ERROR    - Black on red background
idaapi.SCOLOR_PREFIX   - 
idaapi.SCOLOR_BINPREF - Grey
idaapi.SCOLOR_EXTRA   - Blue
idaapi.SCOLOR_ALTOP   - Blue
idaapi.SCOLOR_HIDNAME - Grey
idaapi.SCOLOR_LIBNAME - Sky blue
idaapi.SCOLOR_LOCNAME - Green
idaapi.SCOLOR_CODNAME - Dark blue
idaapi.SCOLOR_ASMDIR  - Light blue
idaapi.SCOLOR_MACRO   - Purple
idaapi.SCOLOR_DSTR    - Green
idaapi.SCOLOR_DCHAR   - Green
idaapi.SCOLOR_DNUM    - Green
idaapi.SCOLOR_KEYWORD - Dark blue
idaapi.SCOLOR_REG     - Dark blue
idaapi.SCOLOR_IMPNAME - Pink
idaapi.SCOLOR_SEGNAME - Army green
idaapi.SCOLOR_UNKNAME - Dark blue
idaapi.SCOLOR_CNAME   - Blue
idaapi.SCOLOR_UNAME   - Dark blue
idaapi.SCOLOR_COLLAPSED - Blue
idaapi.SCOLOR_ADDR      - 
"""



def color_inject(a_str, old_color, new_color):
    SCOLOR_OFF = idaapi.SCOLOR_OFF
    SCOLOR_ON = idaapi.SCOLOR_ON
    ret_str = SCOLOR_OFF + old_color
    ret_str += SCOLOR_ON + new_color + a_str + SCOLOR_OFF + new_color
    ret_str += SCOLOR_ON + old_color
    return ret_str

class IdpHooker(idaapi.IDP_Hooks):
    def __init__(self, *args):
        self.am_in_hook = False
        self.active = True
        super(IdpHooker, self).__init__()

    def toggle_active(self):
        self.active = not self.active
  
    def get_reg_name(self, *args):
        """
        This function is here to fix a bug in the idapython overloading
        """
        ret = _idaapi.IDP_Hooks_get_reg_name(self, *args)
        if ret == None:
          return 0
        return ret
        
    def custom_mnem(self, *args):
        """
        custom_out(self) -> bool
        Return 0 - No customization
        Return 2 - Did customization
        """
        if self.am_in_hook or not self.active:
          return hook_place.IDP_Hooks_custom_mnem(self, *args)
        for checker, color in INSN_RULES:
            if checker(idaapi.cmd.ea):
                self.am_in_hook = True
                mnem = idaapi.ua_mnem(idaapi.cmd.ea)
                self.am_in_hook = False
                mnem = mnem + " " * (7 - len(mnem))
                return color_inject(mnem, idaapi.SCOLOR_INSN, color)
        return hook_place.IDP_Hooks_custom_mnem(self, *args)

def JumpToTop():
    curr_ea = idaapi.get_screen_ea()
    curr_func = idaapi.get_func(curr_ea)
    if not curr_func:
        return
    begin = curr_func.startEA
    idaapi.jumpto(begin)
    
def JumpToBottom():
    curr_ea = idaapi.get_screen_ea()
    curr_func = idaapi.get_func(curr_ea)
    if not curr_func:
        return
    begin = idaapi.prevaddr(curr_func.endEA)
    idaapi.jumpto(begin)    
    
class InsnColorizer(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = GLB_PluginName
    wanted_hotkey = GLB_HotKey

    def init(self):
        idaapi.add_hotkey("j", JumpToBottom)
        idaapi.add_hotkey("i", JumpToTop)
        self.hook = IdpHooker()
        self.hook.hook()
        print "%s initialized" % (GLB_PluginName)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.hook.toggle_active()
        idaapi.request_refresh(idaapi.IWID_DISASMS)
            
    def term(self):
        self.hook.unhook()


def PLUGIN_ENTRY():
    return InsnColorizer()