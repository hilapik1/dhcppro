import mysql.connector

class DBHandler:
    def __init__(self, host, user, password, database):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.connection = None
        self.initialize()

    def initialize(self):
        self.connection = mysql.connector.connect(host=self.host, user=self.user,
                                                  password=self.password)  # host='localhost', user="root", password='cyber'
        my_cursor = self.connection.cursor()
        my_cursor.execute("SHOW DATABASES")
        found = False
        for x in my_cursor:
            if self.database in x:
                found = True
                break

        if not found:
            # create database and tables
            my_cursor = self.connection.cursor()
            my_cursor.execute(f"CREATE DATABASE {self.database}")
            my_cursor = self.connection.cursor()
            # mycursor.execute("CREATE TABLE `dhcppro`.`new_table`(`id` INT NOT NULL, `mac_address` VARCHAR(45) NULL, PRIMARY KEY(`id`));")
            # CREATE DISCOVER TABLE
            my_cursor.execute(f"CREATE TABLE {self.database}.`discovertable`(`mac_address` VARCHAR(17) NOT NULL"
                              + ",`id` INT NOT NULL,`time_arrivel` DATETIME NULL, `count` INT NULL"
                              + ",`black_list` TINYINT NULL, "
                              + "UNIQUE INDEX `mac_address_UNIQUE`(`mac_address` ASC) VISIBLE"
                              + ", UNIQUE INDEX `id_UNIQUE`(`id` ASC) VISIBLE, PRIMARY KEY(`mac_address`, `id`));")

        # reinitialize connector directly to specific db
        self.connection = mysql.connector.connect(host=self.host, user=self.user, password=self.password,
                                                  database=self.database)

    # def ubsert(self, discover_object):
    #     #insert if count=0 --> count=0+1=1 , update if count=1 --> count=1+1=2
    #     self.analyse.analyse_discover(discover_object)

    def get_cursor(self):
        return self.connection.cursor()

    def select(self):
        pass

        # mycursor = connection.cursor()
        # mycursor.execute("SELECT * FROM dhcppro.customers")
        # myresult = mycursor.fetchall()
        #
        # for x in myresult:
        #     print(x)

        # if connection.is_connected():
        #     db_Info = connection.get_server_info()
        #     print("Connected to MySQL Server version ", db_Info)
        #     cursor = connection.cursor()
        #     cursor.execute("select database();")
        #     record = cursor.fetchone()
        #     print("You're connected to database: ", record)
