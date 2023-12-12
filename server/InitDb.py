import uuid

import datetime
import Answers
import ServerFunction
import sqlite3
PORT_FILE = "port.info.txt"
DEFAULT_PORT = 1357
CLIENTS_DIC = {}
SUCCESS = 1
FAILURE = 0

def read_port_from_file():
    try:
        with open(PORT_FILE, "r") as file_port:
            port = file_port.read()
        return int(port) if port.isnumeric() else DEFAULT_PORT
    except FileNotFoundError:
        print("Warning: file 'port.info.txt' doesn't exist")
        return DEFAULT_PORT
    except ValueError:
        print("Warning: invalid file content")
        return DEFAULT_PORT




def create_clients_table():
    conn = sqlite3.connect(r"server.db")
    conn.text_factory = bytes
    mycursor = conn.cursor()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS clients (
                ID VARCHAR(16) PRIMARY KEY,
                Name VARCHAR(255),
                PublicKey VARCHAR(160),
                LastSeen TIME,
                AES VARCHAR(32),
                EncryptedAES VARCHAR(32)
            );
        """)
        conn.commit()
        return (mycursor, conn)
    except sqlite3.Error as e:
        print(f"Unable to create clients table: {e}")


def get_cursor_and_connection_cleint():
    try:
        conn = sqlite3.connect(r"server.db")
        conn.text_factory = bytes
        mycursor = conn.cursor()
        return mycursor, conn
    except sqlite3.Error as e:
        print(f"Unable to connect to the database: {e}")
        return None, None


def create_client_table():
    mycursor, conn = get_cursor_and_connection_cleint()

    if mycursor is not None and conn is not None:
        create_clients_table(conn)
        return mycursor, conn
    else:
        return None, None



def create_files_table():
    sql_create_files_table = """ CREATE TABLE IF NOT EXISTS files (
                                                       ID VARCHAR(16),
                                                       FileName VARCHAR(255),
                                                       PathName VARCHAR(255) PRIMARY KEY,
                                                       Verified VARCHAR(1)
                                                   ); """

    mycursor, myconn = ServerFunction.get_curser_serverDB()
    try:
        mycursor.execute(sql_create_files_table)
        myconn.commit()
        return (mycursor, myconn)
    except:
        print("unable to open files table")
        myconn.close()
        return (0,0)

def load_clients_db():
    try:
        mycursor, myconn = ServerFunction.get_curser_serverDB()
        mycursor.execute("SELECT ID, Name, PublicKey, AES, EncryptedAES FROM clients")
        clients_data = mycursor.fetchall()

        for client_data in clients_data:
            client_id, name, pubkey, aeskey, encrypted_aeskey = client_data
            CLIENTS_DIC[client_id] = {
                'Name': name,
                'PublicKey': pubkey,
                'AESKey': aeskey,
                'EncryptedAESKey': encrypted_aeskey
            }

    except sqlite3.Error as e:
        print(f"Error loading clients from the database: {e}")

    finally:
        myconn.close()


def add_client_reg(mycursor, myconn, userName):
    uid = uuid.uuid1()
    success = add_client(mycursor, myconn, userName, uid)
    if success:
        return Answers.send_reg_success(uid)
    else:
        return Answers.send_reg_failed()

def add_client(mycursor, myconn, userName, uid):
    sql = 'INSERT INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)'
    val = [uid.bytes, userName, datetime.datetime.now()]
    try:
        mycursor.execute(sql, val)
        myconn.commit()
    except Exception as e:
        print(f"Failed to add clients details: {e}")
        return 0
    finally:
        myconn.close()
    return 1




def add_public_key_AES(client_id, user_name, public_key, encrypted_aes, aes_key, encrypted_aes_size):
    mycursor, myconn = ServerFunction.get_curser_serverDB()
    sql = "UPDATE clients SET PublicKey = ?, LastSeen = ?, AES = ?, EncryptedAES = ? WHERE ID = ?"
    val = [public_key, datetime.datetime.now(), aes_key, encrypted_aes, client_id]

    try:
        mycursor.execute(sql, val)
        myconn.commit()
        myconn.close()
        CLIENTS_DIC[client_id] = [user_name, public_key, aes_key, encrypted_aes]  # saving client details to memory
    except:
        print("failed to enter public key to clients")
        myconn.close()
        return Answers.send_req_failed()
    return Answers.send_recv_public_send_AES(client_id, encrypted_aes, encrypted_aes_size)




def get_AES_client(client_id):
    if client_id in CLIENTS_DIC:
        client_det = CLIENTS_DIC[client_id]
        client_aes = client_det.get('AESKey')

        if isinstance(client_aes, list):
            return client_aes[0][0]

        return client_aes
    else:
        return None


def get_encryptedAES_client(client_id):
    if client_id in CLIENTS_DIC:
        client_det = CLIENTS_DIC[client_id]
        client_aes = client_det.get('EncryptedAESKey')
        return client_aes
    else:
        return None



def get_AES_client_or_register(client_id, user_name):
    client_aes = get_encryptedAES_client(client_id)
    if client_aes is None:  # If userName or AES are not in the table
        uid = uuid.uuid1()
        mycursor, myconn = ServerFunction.get_curser_serverDB()

        success = add_client(mycursor, myconn, user_name, uid)

        if success:
            return Answers.send_reConnect_failed(client_id)
        else:
            return Answers.send_req_failed()
    else:
        if isinstance(client_aes, tuple):
            client_aes = (client_aes[0])[0]
        encrypted_aes_size = len(client_aes)
        return Answers.send_reConnect_success(client_id, client_aes, encrypted_aes_size)


def update_last_seen(clientId):
    mycursor, myconn = ServerFunction.get_curser_serverDB()
    sql = "UPDATE clients SET LastSeen = ? WHERE ID = ?"
    val = [datetime.datetime.now(), clientId]
    try:
        mycursor.execute(sql, val)
        myconn.commit()
    except:
        print("failed to update last seen")
        return 0
    myconn.close()
    return 1


def save_file_to_table(clientId, fileName, filePath):
    mycursor, myconn = create_files_table()
    if(myconn==0):
        return 0
    sql = "DELETE FROM files WHERE PathName = '" + filePath + "'"
    sql1 = "INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?,?,?,?)"
    val = [clientId, fileName, filePath, 0]
    try:
        mycursor.execute(sql)  # deleting file details if user resending same file
        mycursor.execute(sql1, val)  # entring clients data to table
        myconn.commit()
        myconn.close()
    except:
        print("failed to enter file details")
        return 0
    return 1


def add_verifiy_CRC(clientId, fileName):
    mycursor, myconn = ServerFunction.get_curser_serverDB()
    sql = "UPDATE files SET Verified = ? WHERE ID = ? AND FileName = ?"
    val = [1, clientId, fileName]
    try:
        mycursor.execute(sql, val)
        myconn.commit()
        myconn.close()
    except:
        print("failed to enter verfication CRC for file")
        return Answers.send_req_failed()
    return Answers.send_message_success(clientId)
