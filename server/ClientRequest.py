import struct
import Encoding
import Answers
import InitDb
import ServerFunction

CODE_SPLIT = 23


def def_request(req_data):
    # Define request functions with corresponding codes
    req_func = {
        1025: register,
        1026: accept_public_key,
        1027: sign_in,
        1028: get_file,
        1029: correct_CRC,
        1030: uncorrect_CRC,
        1031: uncorrect_CRC_4
    }

    # Unpack the request data
    (client_id, version, code, payload_size), payload = \
        struct.unpack('<16scHI', req_data[:CODE_SPLIT]), req_data[CODE_SPLIT:]

    payload = payload[:payload_size]
    # Check if the code request is correct and call the corresponding function
    if code in req_func:
        return req_func[code](client_id, payload_size, payload)
    else:
        print("Invalid code")
        return Answers.send_reg_failed()


def register(client_id, payload_size, req_details):
    # Extract username and request data
    user_name, req_data = ServerFunction.get_req(req_details)
    user_name = user_name[:user_name.find(b'\0')]

    # Create clients table if it doesn't exist
    if not InitDb.CLIENTS_DIC:
        my_cursor, my_conn = InitDb.create_clients_table()
        if my_conn == 0:
            return Answers.send_reg_failed()
        my_cursor.close()

    # Check if the username is already registered
    if user_name in InitDb.CLIENTS_DIC:
        return Answers.send_reg_failed()

    my_cursor, my_conn = ServerFunction.get_curser_serverDB()
    return InitDb.add_client_reg(my_cursor, my_conn, user_name)


def accept_public_key(client_id, payload_size, req_details):
    # Extract username and request data
    user_name, req_data = ServerFunction.get_req(req_details)
    # Update last seen timestamp for the client
    result = InitDb.update_last_seen(client_id)
    if result == 0:
        return Answers.send_reg_failed()
    # Unpack the public key from the request data
    public_key = struct.unpack('<160s', req_data)
    if type(public_key) is tuple:
        public_key = public_key[0]
    # Create and return the encrypted AES key
    return ServerFunction.create_encrypt_AES(client_id, user_name, public_key)


def sign_in(client_id, payload_size, req_details):
    # extract username and request data
    user_name, req_data = ServerFunction.get_req(req_details)
    user_name = user_name[:user_name.find(b'\0')]

    # update last seen timestamp for the client
    result = InitDb.update_last_seen(client_id)
    if result == 0:
        return Answers.send_reg_failed()

    return InitDb.get_AES_client_or_register(client_id, user_name)


def get_file(client_id, payload_size, req_details):
    # Unpack data from request details
    unpack_format = f'<I255s{payload_size-4-255}s'
    decrypted_file_size, file_name, message_content = struct.unpack(unpack_format, req_details)
    file_name = file_name[:file_name.find(b'\0')]

    aes_key = InitDb.get_AES_client(client_id)

    # Decrypt the message content with AES
    decrypted_file = Encoding.aes_decryption(aes_key, message_content)

    # Save the file in the server
    file_path = ServerFunction.save_file_in_server(file_name, decrypted_file)
    if file_path == 0:
        return Answers.send_reg_failed()

    # Enter the file into the files table
    success = InitDb.save_file_to_table(client_id, file_name, file_path)

    # Update last seen timestamp for the client
    ans = InitDb.update_last_seen(client_id)

    # Check for success and update the client
    if success == 1 and ans == 1:
        decoded_file, decoded = ServerFunction.decode_decrypted_file(decrypted_file)
        if decoded_file == 0:
            return Answers.send_reg_failed()
        # Calculate the CRC and send it to the client
        cksum = Encoding.calculate_crc32(decoded_file)
        return Answers.send_correct_file_CRC(client_id, decrypted_file_size, file_name, cksum)
    else:
        return Answers.send_reg_failed()


def correct_CRC(client_id, payload_size, req):
    # Update last seen timestamp for the client
    ans = InitDb.update_last_seen(client_id)
    if ans == 0:
        return Answers.send_reg_failed()

    # Extract filename and request data
    file_name, req_data = ServerFunction.get_req(req)
    file_name = file_name[:file_name.find(b'\0')]

    # Add verification of CRC in the files table
    return InitDb.add_verifiy_CRC(client_id, file_name)


def uncorrect_CRC(client_id, payload_size, req):
    # Update last seen timestamp for the client
    ans = InitDb.update_last_seen(client_id)
    if ans == 0:
        return Answers.send_reg_failed()
    # Placeholder for uncorrected CRC, if needed
    return None

def uncorrect_CRC_4(client_id, payload_size, req):
    # Update last seen timestamp for the client
    ans = InitDb.update_last_seen(client_id)
    if ans == 0:
        return Answers.send_reg_failed()

    # Send a success message
    return Answers.send_reg_success()
