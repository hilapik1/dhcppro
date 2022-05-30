from tkinter import *
from tkinter import ttk
import sqlite3
from DBHandler import DBHandler, QueryAckTableStatus

class Creation:

    def __init__(self):
       pass


    def create_var(self, db_handler):
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
        #self.query_database() #####
        self.c = None
        self.list=[]

    def handleDB(self):
        self.root.after(1000, self.updateGui)

    def mainLoop(self):
        self.root.mainloop()

    def updateGui(self):

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

    def query_database(self):
        #create a db or connect tp one that exists
        #conn=sqlite3.connect('dhcppro.db')
        #create a cursor instance
        self.c = DBHandler('localhost', "root", 'cyber', 'dhcppro')


    def get_root(self):
        return self.root

    def design_the_table(self):
        # Add Some Style
        style = ttk.Style()

        # Pick A Theme
        style.theme_use('default')

        # Configure the Treeview Colors
        style.configure("Treeview",
                        background="#D3D3D3",
                        foreground="black",
                        rowheight=25,
                        fieldbackground="#D3D3D3")

        # Change Selected Color
        style.map('Treeview',
                  background=[('selected', "#347083")])

    def create_Treeview_Frame(self):
        # Create a Treeview Frame
        self.tree_frame = Frame(self.root)
        self.tree_frame.pack(pady=10)

    def create_scrollbar(self):
        # Create a Treeview Scrollbar
        self.tree_scroll = Scrollbar(self.tree_frame)
        self.tree_scroll.pack(side=RIGHT, fill=Y)

    def create_Treeview(self):
        # Create The Treeview
        self.my_tree = ttk.Treeview(self.tree_frame, yscrollcommand=self.tree_scroll.set, selectmode="extended")

        self.my_tree.tag_configure('oddrow', background="white")
        self.my_tree.tag_configure('evenrow', background="lightblue")

        self.my_tree.pack()

    def configure_scrollbar(self):
        # Configure the Scrollbar
        self.tree_scroll.config(command=self.my_tree.yview)

    def create_table(self):
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

    def insert(self, mac_address):
        # Add Fake Data
        #self.data = data
        if self.c is None:
            self.query_database()
        print("queryyyyyyyyyyyyyyyyyyyyyyyyyyy")
        self.c.get_cursor().execute(f"SELECT * FROM dhcppro.acktable where mac_address ='{mac_address}';")
        for cursor in self.c.get_cursor():
            for i in range(len(cursor)):
                self.list.append(cursor[i])
        print("queryyyyyyyyyyyyyyyyyyyyyyy")
        print(type(self.c.get_cursor()))
        print("7777777777777777777777777777777777777777777777")
        self.create_striped_rows()
        print("gfddwddasdaa")
        # data = [
        #     ["John", "Elder", 1, "123 Elder St.", "Las Vegas", "NV", "89137"],
        #     ["Mary", "Smith", 2, "435 West Lookout", "Chicago", "IL", "60610"],
        #     ["Tim", "Tanaka", 3, "246 Main St.", "New York", "NY", "12345"],
        #     ["Erin", "Erinton", 4, "333 Top Way.", "Los Angeles", "CA", "90210"],
        #     ["Bob", "Bobberly", 5, "876 Left St.", "Memphis", "TN", "34321"],
        #     ["Steve", "Smith", 6, "1234 Main St.", "Miami", "FL", "12321"],
        #     ["Tina", "Browne", 7, "654 Street Ave.", "Chicago", "IL", "60611"],
        #     ["Mark", "Lane", 8, "12 East St.", "Nashville", "TN", "54345"],
        #     ["John", "Smith", 9, "678 North Ave.", "St. Louis", "MO", "67821"],
        #     ["Mary", "Todd", 10, "9 Elder Way.", "Dallas", "TX", "88948"],
        #     ["John", "Lincoln", 11, "123 Elder St.", "Las Vegas", "NV", "89137"],
        #     ["Mary", "Bush", 12, "435 West Lookout", "Chicago", "IL", "60610"],
        #     ["Tim", "Reagan", 13, "246 Main St.", "New York", "NY", "12345"],
        #     ["Erin", "Smith", 14, "333 Top Way.", "Los Angeles", "CA", "90210"],
        #     ["Bob", "Field", 15, "876 Left St.", "Memphis", "TN", "34321"],
        #     ["Steve", "Target", 16, "1234 Main St.", "Miami", "FL", "12321"],
        #     ["Tina", "Walton", 17, "654 Street Ave.", "Chicago", "IL", "60611"],
        #     ["Mark", "Erendale", 18, "12 East St.", "Nashville", "TN", "54345"],
        #     ["John", "Nowerton", 19, "678 North Ave.", "St. Louis", "MO", "67821"],
        #     ["Mary", "Hornblower", 20, "9 Elder Way.", "Dallas", "TX", "88948"]
        #
        # ]


    def delete(self):
        #if he doesnt renew the connection need to delete from table
        pass

    def edit(self):
        # Get selected item to Edit
        selected_item = tree.selection()[0]
        print(selected_item)
        print("hhhhhhhhhhhhhhhhh")
        tree.item(selected_item, text="blub", values=("foo", "bar"))

    def update(self,data,index):
        #check how to do it
        self.data = data
        #_iid = self.my_tree.identify_row(index.y)
        selected = self.my_tree.focus()
        print(selected)
        #print(_iid)

        # count=0
        # for row in self.my_tree:
        #     count+=1
        #     if count==index:
        #         self.my_tree.selection_set(self.data)
        # #למצוא את השורה בטבלה ולשנות את מה ששונה
        # self.my_tree.delete()

    def create_striped_rows(self):
        # Create Striped Row Tags
        self.my_tree.tag_configure('oddrow', background="white")
        self.my_tree.tag_configure('evenrow', background="lightblue")
        print("^^^^^%%%%%%%%%%%%%%%%%%%%%%%%%%%%%$$$$$$$$$$$$$$$$$$$")
        # Add our data to the screen
        count = 0
        for i in range (10): #33333333333333333333333333for checking
            for record in self.list:
                if count % 2 == 0:
                    self.my_tree.insert(parent='', index='end', iid=count, text='',
                                   values=(record[0], record[1], record[2], record[3], record[4], record[5], record[6]),
                                   tags=('evenrow',))
                    self.dict={record[0]:count}
                else:
                    self.my_tree.insert(parent='', index='end', iid=count, text='',
                                   values=(record[0], record[1], record[2], record[3], record[4], record[5], record[6]),
                                   tags=('oddrow',))
                # increment counter
                count += 1



    def dont_know_if_needed(self):
        # Add Record Entry Boxes
        data_frame = LabelFrame(self.root, text="Record")
        data_frame.pack(fill="x", expand="yes", padx=20)
        fn_label = Label(data_frame, text="First Name")
        fn_label.grid(row=0, column=0, padx=10, pady=10)
        fn_entry = Entry(data_frame)
        fn_entry.grid(row=0, column=1, padx=10, pady=10)

        ln_label = Label(data_frame, text="First Name")
        ln_label.grid(row=0, column=2, padx=10, pady=10)
        ln_entry = Entry(data_frame)
        ln_entry.grid(row=0, column=3, padx=10, pady=10)

        id_label = Label(data_frame, text="First Name")
        id_label.grid(row=0, column=4, padx=10, pady=10)
        id_entry = Entry(data_frame)
        id_entry.grid(row=0, column=5, padx=10, pady=10)

        address_label = Label(data_frame, text="First Name")
        address_label.grid(row=1, column=0, padx=10, pady=10)
        address_entry = Entry(data_frame)
        address_entry.grid(row=1, column=1, padx=10, pady=10)

        city_label = Label(data_frame, text="First Name")
        city_label.grid(row=1, column=2, padx=10, pady=10)
        city_entry = Entry(data_frame)
        city_entry.grid(row=1, column=3, padx=10, pady=10)

        state_label = Label(data_frame, text="First Name")
        state_label.grid(row=1, column=4, padx=10, pady=10)
        state_entry = Entry(data_frame)
        state_entry.grid(row=1, column=5, padx=10, pady=10)

        zipcode_label = Label(data_frame, text="First Name")
        zipcode_label.grid(row=1, column=6, padx=10, pady=10)
        zipcode_entry = Entry(data_frame)
        zipcode_entry.grid(row=1, column=7, padx=10, pady=10)

        # Add Buttons
        button_frame = LabelFrame(self.root, text="Commands")
        button_frame.pack(fill="x", expand="yes", padx=20)

        update_button = Button(button_frame, text="Update Record")
        update_button.grid(row=0, column=0, padx=10, pady=10)

        add_button = Button(button_frame, text="Add Record")
        add_button.grid(row=0, column=1, padx=10, pady=10)

        remove_all_button = Button(button_frame, text="Remove All Records")
        remove_all_button.grid(row=0, column=2, padx=10, pady=10)

        remove_one_button = Button(button_frame, text="Remove One Selected")
        remove_one_button.grid(row=0, column=3, padx=10, pady=10)

        remove_many_button = Button(button_frame, text="Remove Many Selected")
        remove_many_button.grid(row=0, column=4, padx=10, pady=10)

        move_up_button = Button(button_frame, text="Move Up")
        move_up_button.grid(row=0, column=5, padx=10, pady=10)

        move_down_button = Button(button_frame, text="Move Down")
        move_down_button.grid(row=0, column=6, padx=10, pady=10)

        select_record_button = Button(button_frame, text="Select Record")
        select_record_button.grid(row=0, column=7, padx=10, pady=10)

def main():
    create_gui = Creation()
    create_gui.create_var(DBHandler(host='localhost', user="root", password='cyber',database='dhcppro'))


if __name__ == "__main__":
    main()