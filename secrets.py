import keyring


def receive_serve_secrets():
    keyring.set_password('Receive_Serve', 'Token', '')
    keyring.set_password('Receive_Serve', 'Aes_Key', '')
    keyring.set_password('Receive_Serve', 'Corp_Id', '')
