import gdb

class PrintGDB(gdb.Command):
    def __init__(self):
        super().__init__("solp", gdb.COMMAND_USER)
    def invoke(self,arg,from_tty):
        gdb.execute('b*0x401933')
        gdb.execute('r')
        a = ''
        for _ in range(100):
            try:
                res = gdb.selected_frame().read_register('rdi')
                gdb.execute('c')
                a += chr(res)
            except : break
        print(a)

PrintGDB()