import time
import random
import json

import Simulator.communication
try:
    import openfhe
except Exception:
    openfhe = None

from Simulator.exceptions import SimulationError, SimVerificationFailedError
from Simulator.report import Report
from Simulator.globals import (
    HOST_SPEED,
    PRINT_LOGS
)

from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric import (
   padding, rsa
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class SmartMeter:
    
    def __init__(
        self, 
    ):
        # Public
        self.id = None
        self.public_key = None
        
        # Simulation data
        self.logs = []
        self.is_cool = None
        self.sim_id = None
        self.fake_keys = None
        
        # Parameters
        self.processor_speed = None # In MHz
        self.communication_speed = None # In kbps
        self.malicious_type = None
        self.consumer_data = None
        self.fake_data = None
        self.typical_data_sum = None
        self.is_dummy = None
        
        # Variables
        self.private_key = None
        self.sym_key = None
        self.predecessor_report = None
        self.verifier_report = None
        self.report = None
    
    @classmethod
    def factory(
        cls, 
        processor_speed=None,
        communication_speed=None,
        malicious_type=None,
        malicious_data=None,
        consumer_data=None,
        typical_data_sum=None,
        sim_id=None,
        is_dummy=False,
        fake_keys=False
    ):
        """This method is used to create a new instance of the class, before simulation starts"""
        obj = cls()
        obj.processor_speed = processor_speed
        obj.communication_speed = communication_speed
        obj.malicious_type = malicious_type
        obj.consumer_data = consumer_data
        obj.typical_data_sum = typical_data_sum
        obj.sim_id = sim_id
        obj.is_cool = False
        obj.is_dummy = is_dummy
        obj.fake_keys = fake_keys
        
        if malicious_type == "manipulate_report":
            if malicious_data is None:
                # obj.fake_data = Report([typical_data_sum for _ in range(len(consumer_data))])
                obj.fake_data = Report([typical_data_sum//len(consumer_data)-1 for _ in range(len(consumer_data))])
            else:
                obj.fake_data = Report(malicious_data)
        
        return obj
    
    def log(self, message, data=None, level="info"):
        self.logs.append({
            "message": message,
            "data": data,
            "time": time.time(),
            "id": self.id,
            "sim_id": self.sim_id,
            "level": level
        })
        if PRINT_LOGS:
            print(f"[{self.sim_id}] {time.time()} {level}: {message}")
    
    def error(self, message, exception=None, data=None):
        self.log(message, data=data, level="error")
        self.logs[-1]["exception"] = exception
    
    def warning(self, message, data=None):
        self.log(message, data=data, level="warning")
    
    def sim_adjust_time(self, time:float):
        # Adjusts the time based on the simulation speed in relation to host machine speed
        if self.is_dummy:
            return 0 # Host machine is considered to be infinitely fast
        return time * (HOST_SPEED/self.processor_speed)
    def sim_transport_time(self, data_size):
        # Calculates the time it takes to transport data
        if self.is_dummy:
            return 0 # Host machine is considered to be infinitely fast
        return data_size * 8 / 1000 / self.communication_speed
    
    def malicious_action(self, communication:'communication.Communication') -> bool:
        if self.malicious_type == None:
            return False
        elif self.malicious_type == "timeout":
            communication.timed_out = True
            return True
        elif self.malicious_type == "corrupt_response":
            communication.corrupt_response = True
            return True
        elif self.malicious_type == "corrupt_report":
            if communication.message == "prepare_report":
                self.cmd_prepare_report(communication)
                self.report.is_valid = False
                return True
            return False
        elif self.malicious_type == "manipulate_report":
            if communication.message == "prepare_report":
                    self.cmd_prepare_report(communication, use_fake_data=True)
                    self.report.is_correct = False
                    return True
        elif self.malicious_type == "claim_invalid_report":
            if communication.message == "receive_report":
                raise SimulationError("Report is not valid")
            return False
        elif self.malicious_type == "claim_invalid_verification":
            if communication.message == "compare_reports":
                    raise SimVerificationFailedError("Verification failed")
        else:
            raise ValueError("Invalid malicious type")
    
    def receive(self, communication:'communication.Communication'):
        self.log(f"Received message: {communication.message}")
        if self.malicious_action(communication):
            return
        
        # Receive message and execute according to message
        if communication.message == "send_symmetric_key":
            self.cmd_send_symmetric_key(communication)
        elif communication.message == "receive_report":
            self.cmd_receive_report(communication)
        elif communication.message == "prepare_report":
            self.cmd_prepare_report(communication)
        elif communication.message == "compare_reports":
            self.cmd_compare_reports(communication)
        elif communication.message == "initialize":
            self.cmd_initialize(communication)
        else:
            raise ValueError("Invalid message")
    
    def cmd_send_symmetric_key(self, communication:'communication.Communication'):
        comm = communication
        comm.response = "ok"
        comm.response_data = self.encrypt_symmetric_key(comm.message_data)
    
    def cmd_receive_report(self, communication:'communication.Communication'):
        comm = communication
        report_key = comm.message_data['encryption_key']
        if report_key is None and self.is_dummy:
            report = comm.message_data['report']
        else:
            report_key = self.decrypt_symmetric_key(report_key)
            report = comm.message_data['report']
            report = self.decrypt_report(report, report_key)
        if not report.is_valid:
            self.warning("Received invalid report", {
                "smart_meter": self.sim_id
            })
            raise SimulationError("Report is not valid")
        if comm.message_data['slot'] == "verifier":
            self.verifier_report = report
        elif comm.message_data['slot'] == "previous":
            self.predecessor_report = report
        else:
            raise ValueError("Invalid slot")
        comm.response = "ok"
    
    def cmd_prepare_report(self, communication:'communication.Communication', use_fake_data=False):
        comm = communication
        if use_fake_data:
            report = self.predecessor_report + self.fake_data
        else:
            report = self.predecessor_report + self.consumer_data
        self.report = report
        self.encrypt_report()
        comm.response = "ok"
        comm.response_data = self.report
        comm.enc_response_data = b"b"* comm.response_data.__sizeof__()
    
    def cmd_compare_reports(self, communication:'communication.Communication'):
        comm = communication
        report = self.predecessor_report - self.verifier_report
        self.validate_report(report, comm.message_data)
        comm.response = "ok"
    
    def cmd_initialize(self, communication:'communication.Communication'):
        comm = communication
        self.id = comm.message_data['id']
        self.generate_asymmetric_keys()
        self.generate_symmetric_key()
        comm.response = "ok"
        comm.response_data = self.public_key
        comm.enc_response_data = b"b"* comm.response_data.__sizeof__()
    
    @staticmethod
    @lru_cache(maxsize=128)
    def symmetric_key_cache():
        # When runtime is unimportant, we generate only one key per simulation
        return Fernet.generate_key()
    
    @staticmethod
    @lru_cache(maxsize=128)
    def asymmetric_key_cache():
        # When runtime is unimportant, we generate only one key per simulation
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_key
    
    def generate_asymmetric_keys(self):
        # Generate public and private key
        if self.fake_keys:
            self.private_key, self.public_key = self.asymmetric_key_cache()
            return
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def generate_symmetric_key(self):
        if self.fake_keys:
            self.sym_key = self.symmetric_key_cache()
            return
        # Generate symmetric key
        self.sym_key = Fernet.generate_key()
    
    def encrypt_report(self):
        # Encrypt report
        data = self.report.to_json()
        data = data.encode()
        cipher = Fernet(self.sym_key)
        encrypted_data = cipher.encrypt(data)
        self.report.encrypted_data = encrypted_data
    
    def decrypt_report(self, report:Report, key):
        # Decrypt report
        cipher = Fernet(key)
        _ = cipher.decrypt(report.encrypted_data)
        report.encrypted_data = None
        if not report.is_valid:
            self.warning("Decrypted invalid report", {
                "smart_meter": self.sim_id
            })
            raise SimulationError("Report is not valid")
        return report
    
    def encrypt_symmetric_key(self, public_key):
        # Encrypt symmetric key
        rsa_public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )
        encrypted_fernet_key = rsa_public_key.encrypt(
            self.sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_fernet_key
    
    def decrypt_symmetric_key(self, encrypted_symmetric_key):
        # Decrypt symmetric key
        decrypted_fernet_key = self.private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_fernet_key
    
    def validate_report(self, report:Report, compare_data):
        # Validate report
        if any(x < 0 for x in report):
            self.warning("Verification failed. Report contains negative values", {
                "smart_meter": self.sim_id
            })
            raise SimVerificationFailedError("Report contains negative values")
        # if any(x > compare_data for x in report):
        #     self.warning("Verification failed. Added values are greater than expected", {
        #         "smart_meter": self.sim_id
        #     })
        #     raise SimVerificationFailedError("Verification failed. Added values are greater than expected")
        if sum(report.entries) > compare_data:
            self.warning("Verification failed. Report sum is greater than expected", {
                "smart_meter": self.sim_id
            })
            raise SimVerificationFailedError("Verification failed. Report sum is greater than expected")

class InteractiveNoiseSmartMeter(SmartMeter):
    def __init__(self):
        super().__init__()
        self.is_leader = False
        self.privacy_parameter = None
        self.leader_keys = None
        
        self.noised_data = None
    
    def receive(self, communication:'communication.Communication'):
        self.log(f"Received message: {communication.message}")
        if self.malicious_action(communication):
            return
        
        # Receive message and execute according to message
        if communication.message == "initialize":
            self.cmd_initialize(communication)
        elif communication.message == "send_data":
            self.cmd_send_data(communication)
        elif communication.message == "send_leader_data":
            self.cmd_leader_send_data(communication)
        else:
            raise ValueError("Invalid message")
    
    def cmd_initialize(self, communication:'communication.Communication'):
        comm = communication
        comm.response = "ok"
        self.id = comm.message_data['id']
        self.privacy_parameter = comm.message_data['privacy_parameter']
        if self.is_leader:
            self.generate_asymmetric_keys()
            comm.response_data = self.public_key
            comm.enc_response_data = b"b"* comm.response_data.__sizeof__()
    
    def cmd_send_data(self, communication:'communication.Communication'):
        comm = communication
        
        self.leader_keys = []
        for key in comm.message_data:
            public_key = serialization.load_pem_public_key(
                key,
                backend=default_backend()
            )
            self.leader_keys.append(public_key)
        
        comm.response = "ok"
        comm.response_data = []
        # For each leader, generate a noise mask.
        noise_masks = []
        for i in range(self.privacy_parameter):
            mask = Report([
                random.randint(-100, 100) for _ in range(len(self.consumer_data))
            ])
            noise_masks.append(mask)
        # Add noise to the data
        noised_data = self.consumer_data
        for mask in noise_masks:
            noised_data += mask
        
        comm.response_data.append(noised_data)
        
        # Encrypt the noise masks for each leader
        for i in range(self.privacy_parameter):
            leader_key:rsa.RSAPublicKey = self.leader_keys[i]
            mask:Report = noise_masks[i]
            encrypted_data = leader_key.encrypt(
                mask.to_json().encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            comm.response_data.append(encrypted_data)
        
        # Encode the data for transport
        comm.enc_response_data = b"b"* comm.response_data.__sizeof__()
    
    def cmd_leader_send_data(self, communication:'communication.Communication'):
        comm = communication
        comm.response = "ok"
        
        total_mask = Report([0 for _ in range(len(self.consumer_data))])
        
        for enc_mask in comm.message_data:
            decrypted_mask = self.private_key.decrypt(
                enc_mask,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            mask = Report.from_json(decrypted_mask.decode())
            total_mask += mask
        total_mask = total_mask.negate()
        # By subtracting each individual SM mask from this SM's usage data, the noise cancels out in the aggregation
        masked_data:Report = self.consumer_data + total_mask
        
        comm.response_data = masked_data
        comm.enc_response_data = b"b"* comm.response_data.__sizeof__()

class HomomorphicMultiPartySmartMeter(SmartMeter):
    def __init__(self):
        super().__init__()
        self.crypto_context = None
        self.key_pair = None
        self.group_key = None
    
    def receive(self, communication:'communication.Communication'):
        self.log(f"Received message: {communication.message}")
        if self.malicious_action(communication):
            return
        
        # Receive message and execute according to message
        if communication.message == "initialize":
            self.cmd_initialize(communication)
        elif communication.message == "send_data":
            self.cmd_send_data(communication)
        elif communication.message == "partial_decrypt":
            self.partial_decrypt(communication)
        else:
            raise ValueError("Invalid message")
    
    def cmd_initialize(self, communication:'communication.Communication'):
        comm = communication
        self.id = comm.message_data['id']
        self.crypto_context = comm.message_data['cc']
        if "previous_key" in communication.message_data:
            self.key_pair = self.crypto_context.MultipartyKeyGen(communication.message_data["previous_key"])
        else:
            self.key_pair = self.crypto_context.KeyGen()
        comm.response = "ok"
        comm.response_data = self.key_pair.publicKey
        comm.enc_response_data = b"b"* comm.response_data.__sizeof__()
    
    def cmd_send_data(self, communication:'communication.Communication'):
        self.group_key = communication.message_data
        communication.response = "ok"
        cipher = self.crypto_context.Encrypt(
            self.group_key,
            self.crypto_context.MakePackedPlaintext(
                self.consumer_data.entries
            )
        )
        communication.response_data = cipher
        communication.enc_response_data = b"b"* communication.response_data.__sizeof__()
    
    def partial_decrypt(self, communication:'communication.Communication'):
        communication.response = "ok"
        if communication.message_data.get("mode") == "lead":
            communication.response_data = self.crypto_context.MultipartyDecryptLead(
                communication.message_data.get("report"),
                self.key_pair.secretKey
            )
        else:
            communication.response_data = self.crypto_context.MultipartyDecryptMain(
                communication.message_data.get("report"),
                self.key_pair.secretKey
            )
        communication.enc_response_data = b"b"* communication.response_data.__sizeof__()