import struct

# define response codes as constants
REG_SUCCESS = 2100
REG_FAILED = 2101
PUBLIC_SEND_AES = 2102
CORRECT_FILE_CRC = 2103
MESSAGE_SUCCESS = 2104
RECONNECT_SUCCESS = 2105
RECONNECT_FAILED = 2106
REQ_FAILED = 2107
SERVER_VERSION = b'3'

def send_reg_success(uid):
    format_code = '<cHI16s'
    server_answer = struct.pack(format_code, SERVER_VERSION, REG_SUCCESS, 16, uid.bytes)
    return server_answer

def send_reg_failed():
    format_code = '<cHI'
    server_answer = struct.pack(format_code, SERVER_VERSION, REG_FAILED, 0)
    return server_answer

def send_recv_public_send_AES(client_id, encrypted_aes, encrypted_aes_size):
    format_code = f'<cHI16s{encrypted_aes_size}s'
    server_answer = struct.pack(format_code, SERVER_VERSION, PUBLIC_SEND_AES, 16 + encrypted_aes_size, client_id, encrypted_aes)
    return server_answer

def send_correct_file_CRC(client_id, file_size, file_name, checksum):
    format_code = '<cHI16sI255sI'
    server_answer = struct.pack(format_code, SERVER_VERSION, CORRECT_FILE_CRC, 279, client_id, file_size, file_name, checksum)
    return server_answer

def send_message_success(client_id):
    format_code = '<cHI16s'
    server_answer = struct.pack(format_code, SERVER_VERSION, MESSAGE_SUCCESS, 16, client_id)
    return server_answer

def send_reConnect_success(client_id, encrypted_aes, encrypted_aes_size):
    format_code = f'<cHI16s{encrypted_aes_size}s'
    server_answer = struct.pack(format_code, SERVER_VERSION, RECONNECT_SUCCESS, 16 + encrypted_aes_size, client_id, encrypted_aes)
    return server_answer

def send_reConnect_failed(client_id):
    format_code = '<cHI16s'
    server_answer = struct.pack(format_code, SERVER_VERSION, RECONNECT_FAILED, 16, client_id)
    return server_answer

def send_req_failed():
    format_code = '<cHI'
    server_answer = struct.pack(format_code, SERVER_VERSION, REQ_FAILED, 0)
    return server_answer
