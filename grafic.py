from tkinter import *
from tkinter import ttk
import sqlite3
from DBHandler import DBHandler, QueryAckTableStatus

class Creation:

    def __init__(self):
       pass




    def create_var(self, db_handler):
        '''

        :param db_handler: an object who creates the connection with the DB
        :return: doesn't return anything, just creates the graphic.
        '''
        self.db_handler = db_handler
        self.root = Tk()
        self.root.geometry("1000x500")
        self.design_the_table()
        self.create_Treeview_Frame()
        self.create_scrollbar()
        self.create_Treeview()
        self.configure_scrollbar()
        self.create_table()
        self.handleDB()
        self.mainLoop()
        self.c = None
        self.list=[]

    def handleDB(self):
        '''

        :return: doesn't return anything, just calls to 'updateGui' all 1000 ms = 1 second.
        '''
        self.root.after(1000, self.updateGui)

    def mainLoop(self):
        '''

        :return: doesn't return anything, just calls to mainloop.
        '''
        self.root.mainloop()

    def updateGui(self):
        '''

        :return: doesn't return anything, just delete old data from the Treeview and then add new data.
        '''
        # update data from db...
        self.db_handler.get_reconnect()
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(QueryAckTableStatus().QUERY)

        # delete old data
        for item in self.my_tree.get_children():
            self.my_tree.delete(item)

        #add new data
        count = 0
        for x in my_cursor:
            if count % 2 == 0:
                self.my_tree.insert(parent='', index='end', iid=count, text='',
                                    values=(x[QueryAckTableStatus.ID],
                                            x[QueryAckTableStatus.MAC_ADDRESS],
                                            x[QueryAckTableStatus.IP_ADDRESS],
                                            x[QueryAckTableStatus.SUBNET_MASK],
                                            x[QueryAckTableStatus.TIME_GIVEN],
                                            x[QueryAckTableStatus.EXPIRE],
                                            x[QueryAckTableStatus.LEASE_TIME]),
                                    tags=('evenrow',))
            else:
                self.my_tree.insert(parent='', index='end', iid=count, text='',
                                    values=(x[QueryAckTableStatus.ID],
                                            x[QueryAckTableStatus.MAC_ADDRESS],
                                            x[QueryAckTableStatus.IP_ADDRESS],
                                            x[QueryAckTableStatus.SUBNET_MASK],
                                            x[QueryAckTableStatus.TIME_GIVEN],
                                            x[QueryAckTableStatus.EXPIRE],
                                            x[QueryAckTableStatus.LEASE_TIME]),
                                    tags=('oddrow',))
            count += 1

        self.root.after(1000, self.updateGui)



    def get_root(self):
        '''

        :return: the root
        '''
        return self.root

    def design_the_table(self):
        '''

        :return: doesn't return anytihng, just design the table in the Treeview.
        '''
        # Add Some Style
        style = ttk.Style()

        # Pick A Theme
        style.theme_use('default')

        # Configure the Treeview Colors
        style.configure("Treeview",
                        background="#D3D3D3", #light gray
                        foreground="black",
                        rowheight=25,
                        fieldbackground="#D3D3D3")

        # Change Selected Color
        style.map('Treeview',
                  background=[('selected', "#347083")]) #Dark moderate cyan

    def create_Treeview_Frame(self):
        '''

        :return: doesn't return anytihng, just create Treeview frame
        '''
        # Create a Treeview Frame
        self.tree_frame = Frame(self.root)
        self.tree_frame.pack(pady=10)

    def create_scrollbar(self):
        '''
        :return: doesn't return anytihng, just create scrollbar
        '''
        # Create a Treeview Scrollbar
        self.tree_scroll = Scrollbar(self.tree_frame)
        self.tree_scroll.pack(side=RIGHT, fill=Y)

    def create_Treeview(self):
        '''
        :return: doesn't return anytihng, just create the Treeview
        '''
        # Create The Treeview
        self.my_tree = ttk.Treeview(self.tree_frame, yscrollcommand=self.tree_scroll.set, selectmode="extended")

        self.my_tree.tag_configure('oddrow', background="white")
        self.my_tree.tag_configure('evenrow', background="lightblue")

        self.my_tree.pack()

    def configure_scrollbar(self):
        '''
        :return: doesn't return anytihng, just configure the scrollbar
        '''
        # Configure the Scrollbar
        self.tree_scroll.config(command=self.my_tree.yview)

    def create_table(self):
        '''
        :return: doesn't return anytihng, just create the table in the Treeview
        '''
        # Define Our Columns
        self.my_tree['columns'] = ("ID", "MAC ADDRESS", "IP ADDRESS", "SUBNET MASK", "TIME GIVEN", "EXPIRE", "LEASE TIME")

        # Format Our Columns
        self.my_tree.column("#0", width=0, stretch=NO)
        self.my_tree.column("ID", anchor=CENTER, width=90)
        self.my_tree.column("MAC ADDRESS", anchor=W, width=140)
        self.my_tree.column("IP ADDRESS", anchor=W, width=140)
        self.my_tree.column("SUBNET MASK", anchor=W, width=120)
        self.my_tree.column("TIME GIVEN", anchor=CENTER, width=160)
        self.my_tree.column("EXPIRE", anchor=CENTER, width=160)
        self.my_tree.column("LEASE TIME", anchor=CENTER, width=140)

        # Create Headings
        self.my_tree.heading("#0", text="", anchor=W)
        self.my_tree.heading("ID", text="ID", anchor=CENTER)
        self.my_tree.heading("MAC ADDRESS", text="MAC ADDRESS", anchor=W)
        self.my_tree.heading("IP ADDRESS", text="IP ADDRESS", anchor=W)
        self.my_tree.heading("SUBNET MASK", text="SUBNET MASK", anchor=W)
        self.my_tree.heading("TIME GIVEN", text="TIME GIVEN", anchor=CENTER)
        self.my_tree.heading("EXPIRE", text="EXPIRE", anchor=CENTER)
        self.my_tree.heading("LEASE TIME", text="LEASE TIME", anchor=CENTER)


def main():
    create_gui = Creation()
    create_gui.create_var(DBHandler())


if __name__ == "__main__":
    main()