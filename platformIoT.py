import json
import time
from websocket_server import WebsocketServer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.serialization import load_pem_parameters, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding
import paho.mqtt.client as mqtt
import os
import base64
import time
import hmac
import hashlib
import threading
import numpy

# Some variables
names = []
modes = []
asymmetric_modes = []
symmetric_modes = []
public_keys = []
shared_keys = []
fernet_keys = []
aead_keys = []
hmacs = []

# The callback when there is a new socket client
def new_client(client, server):
    print("New client!")

# The callback when there is a new socket message
def new_message(client2, server, message):
    # Unsubscribe message
    if (str(message).split(": ")[0] == "unsubscribe"):
        client.unsubscribe(str(message).split(": ")[1] + "/from")
        print("Unsubscribe: " + str(message).split(": ")[1])

    # HMAC message
    else:
        hmac_key = str(message)

        # DH o ECDH
        if (asymmetric_mode == 0):
            h2 = hmac.new(bytes(hmac_key, 'ascii'), bytes(str(b_public_key.public_numbers().y), 'ascii'), hashlib.sha256)
        else:
            h2 = hmac.new(bytes(hmac_key, 'ascii'), b_public_key_ecdh.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo), hashlib.sha256)

        # Compare HMAC
        if (hmac.compare_digest(h, h2.hexdigest())):
            hmacs.append(True)
            data = { "type": "datos_dispositivos", "name": name, "mode": mode } # model data
            server.send_message_to_all(json.dumps(data))
            print("HMAC de " + name + " coincide. Añadiendo dispositivo...")
        else:
            hmacs.append(False)
            print("HMAC de " + name + " no coincide. Dispositivo expulsado.")

# Generate DH parameters
parameters = dh.generate_parameters(generator = 2, key_size = 512, backend = default_backend())
params_pem = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

# Generate private and public key
a_private_key = parameters.generate_private_key()
a_public_key = a_private_key.public_key()

# Generate private and public key ECDH
a_private_key_ecdh = ec.generate_private_key(ec.SECP384R1())
a_public_key_ecdh = a_private_key_ecdh.public_key()

# The callback for when the client receives a CONNACK response from the server
def on_connect(client, userdata, flags, rc):
    if (rc == 0):
        print("Connected OK (MQTT)")
        client.subscribe("connection")
    else:
        print("Connected with result code " + str(rc))

# The callback for when a PUBLISH message is received from the server
def on_message(client, userdata, msg):
    global name
    global mode
    global asymmetric_mode
    global symmetric_mode
    global b_public_key
    global b_public_key_ecdh
    global a_shared_key
    global f_key
    global a_key
    global h
    global hmac_key
    print(msg.topic + " -> " + str(msg.payload.decode()))

    # Connection message
    if (msg.topic == "connection"):
        print("Connection message.")

        # Initialize some variables
        name = str(msg.payload.decode()).split(":")[0]
        mode = str(msg.payload.decode()).split(":")[1]
        asymmetric_mode = int(str(msg.payload.decode()).split(":")[2])
        symmetric_mode = int(str(msg.payload.decode()).split(":")[3])

        # Save the variables for each device
        names.append(name)
        modes.append(mode)
        asymmetric_modes.append(asymmetric_mode)
        symmetric_modes.append(symmetric_mode)

        # Key exchange
        if (asymmetric_mode == 0):
            client.publish(name + "/to", "param:" + str(params_pem, 'ascii'))
            client.publish(name + "/to", "public:" + str(a_public_key.public_numbers().y))
        else:
            client.publish(name + "/to", "public:" + a_public_key_ecdh.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo).decode())
        client.subscribe(name + "/from")
        print("Public key sent to device.")

        # Show the information on web page
        data = { "type": "conexion_dispositivo", "payload": msg.payload.decode() }
        server.send_message_to_all(json.dumps(data))

    # Message from a device that has already connected
    else:

        # Topic = <Device name>/from
        name = str(msg.topic).split("/")[0]
        if (msg.topic == (name + "/from")):

            # Receive device public key
            if (str(msg.payload.decode()).split(":")[0] == "public"):

                # If we know its old public key, we upload it
                try:
                    public_keys.pop(names.index(name))
                    shared_keys.pop(names.index(name))
                    fernet_keys.pop(names.index(name))
                    aead_keys.pop(names.index(name))
                    print("Public key uploaded from device.")

                # If we don't know its public key, we save it
                except IndexError:
                    # If the device has 'output' or nothing
                    if (int(mode) > 0):
                        # HMAC key will be introduced on web page
                        data = { "type": "hmac", "name": name, "mode": mode }

                    # If the device has just 'input'
                    else:
                        # HMAC key will be introduced on device
                        hmac_key = str(os.urandom(2).hex())
                        data = { "type": "hmac", "name": name, "mode": mode, "hmac_key": hmac_key }

                    # Show the correspondent information on web page
                    server.send_message_to_all(json.dumps(data))

                    print("New public key from device.")

                # DH key exchange
                if (asymmetric_modes[names.index(name)] == 0):
                    b_public_key_number = int(str(msg.payload.decode()).split(":")[1])
                    peer_public_numbers = dh.DHPublicNumbers(b_public_key_number, parameters.parameter_numbers())
                    b_public_key = peer_public_numbers.public_key(default_backend())
                    public_keys.insert(names.index(name), b_public_key)
                    a_shared_key = a_private_key.exchange(b_public_key)

                # ECDH key exchange
                else:
                    b_public_key_number = str(msg.payload.decode()).split(":")[1]
                    b_public_key_ecdh = load_pem_public_key(b_public_key_number.encode())
                    a_shared_key = a_private_key_ecdh.exchange(ec.ECDH(), b_public_key_ecdh)

                print("Shared key calculated.")
                # Save the shared key
                shared_keys.insert(names.index(name), a_shared_key)

                # We fix the shared key for Fernet using HASH and save it
                derived_key_fernet = HKDF(algorithm = hashes.SHA256(), length = 32, salt = None, info = b'handshake data').derive(a_shared_key)
                key_fernet = base64.urlsafe_b64encode(derived_key_fernet)
                f_key = Fernet(key_fernet)
                fernet_keys.insert(names.index(name), f_key)

                # We fix the shared key for AEAD using HASH and save it
                derived_key_aead = HKDF(algorithm = hashes.SHA256(), length = 24, salt = None, info = b'handshake data').derive(a_shared_key)
                key_aead = base64.urlsafe_b64encode(derived_key_aead)
                a_key = aead.AESGCM(key_aead)
                aead_keys.insert(names.index(name), a_key)

            # Receive HMAC from device
            elif (str(msg.payload.decode()).split(":")[0] == "hmac"):

                # Save received HMAC
                print("HMAC recibida del dispositivo.")
                h = str(msg.payload.decode()).split(":")[1]

                # If the device has just 'input'
                if (int(mode) == 0):
                    # DH or ECDH
                    if (asymmetric_mode == 0):
                        h2 = hmac.new(bytes(hmac_key, 'ascii'), bytes(str(b_public_key.public_numbers().y), 'ascii'), hashlib.sha256)
                    else:
                        h2 = hmac.new(bytes(hmac_key, 'ascii'), b_public_key_ecdh.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo), hashlib.sha256)

                    # Compare HMAC
                    if (hmac.compare_digest(h, h2.hexdigest())):
                        hmacs.append(True)
                        data = { "type": "datos_dispositivos", "name": name, "mode": mode }
                        # Device will be added on web page if HMAC is correct
                        server.send_message_to_all(json.dumps(data))
                        print("HMAC de " + name + " coincide. Añadiendo dispositivo...")
                    else:
                        hmacs.append(False)
                        # Unsubscribe
                        client.unsubscribe(name + "/from")
                        print("HMAC de " + name + " no coincide. Dispositivo expulsado.")

            # Receive message from device
            elif (str(msg.payload.decode()).split(": ")[0] == "message"):
                message = str(msg.payload.decode()).split(": ")[1]

                # Fernet or AEAD
                if (symmetric_modes[names.index(name)] == 0):
                    message = fernet_keys[names.index(name)].decrypt(message.encode())
                else:
                    message = aead_keys[names.index(name)].decrypt(b"12345678", message.encode('latin-1'), None)
                print("Message from " + name + ": " + message.decode())

                # Show the correspondent information on web page
                data = { "type": "message", "name": name, "payload": message.decode() } # model data
                server.send_message_to_all(json.dumps(data))


# Create MQTT client
client = mqtt.Client("Plataforma")
# Function for new connection
client.on_connect = on_connect
# Function for new message
client.on_message = on_message
# Server y port MQTT 
client.connect("192.168.0.17", 1883)
# Start new thread
client.loop_start()

# Create web socket server
server = WebsocketServer(9001)
server.set_fn_new_client(new_client)
server.set_fn_message_received(new_message)

# Start new thread
threading.Thread(target = server.run_forever).start()

# Loop
while 1:

    # Key rotation
    time.sleep(300)
    print("Updating keys...")

    # Generate DH parameters
    parameters = dh.generate_parameters(generator = 2, key_size = 512, backend = default_backend())
    params_pem = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

    # Generate private and public key
    a_private_key = parameters.generate_private_key()
    a_public_key = a_private_key.public_key()

    # Generate private and public key ECDH
    a_private_key_ecdh = ec.generate_private_key(ec.SECP384R1())
    a_public_key_ecdh = a_private_key_ecdh.public_key()

    # Send to devices new key
    for x in names:
        # DH or ECDH
        if (asymmetric_modes[names.index(x)] == 0):
            client.publish(name + "/to", "param:" + str(params_pem, 'ascii'))
            client.publish(name + "/to", "public:" + str(a_public_key.public_numbers().y))
        else:
            client.publish(name + "/to", "public:" + a_public_key_ecdh.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo).decode())

    print("New keys send.")
