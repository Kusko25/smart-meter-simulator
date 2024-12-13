import cProfile
import pstats

from Simulator.exceptions import SimulationError, SimTimeoutError, SimCorruptResponseError
import Simulator.director as director
import Simulator.smart_meter as smart_meter

class Communication:
    def __init__(self):
        self.message:str = None
        self.message_data = None
        self.enc_message_data:bytes = None # Actual data in json format
        
        self.receiver:smart_meter.SmartMeter = None
        self.sender:director.Director = None
        self.timeout:int = None
        
        self.response:str = None
        self.response_data = None
        self.enc_response_data:bytes = None # Actual data in json format
        
        self.time_passed = None
        
        self.exception = None
        
        self.batch_id = None
        
        # Flags the receiver can set to simulate errors
        self.timed_out:bool = False
        self.corrupt_response:bool = False
    
    _batch_id = 0
    @classmethod
    def generate_batch_id(cls):
        cls._batch_id += 1
        return cls._batch_id
    
    @property
    def bytes_transmitted(self):
        res = 0
        if self.enc_message_data:
            res += len(self.enc_message_data)
        if self.enc_response_data:
            res += len(self.enc_response_data)
        return res
    
    def send(self):
        if self.message_data and not isinstance(self.enc_message_data, bytes):
            raise ValueError("enc_message_data must be bytes")
        payload_size = len(self.message.encode() + b'+' + self.enc_message_data)
        self.response_data = None
        self.enc_response_data = b""
        self.sender.commands_sent += 1
        with cProfile.Profile() as pr:
            try:
                self.receiver.receive(self)
                pr.create_stats()
            except SimulationError as e:
                pr.create_stats()
                self.exception = e
                self.response = "error"
                self.response_data = str(e)
                self.enc_response_data = self.response_data.encode()
            ps = pstats.Stats(pr)
            time_passed:float = ps.total_tt
        
        if self.response_data and not isinstance(self.enc_response_data, bytes):
            raise ValueError("enc_response_data must be bytes")
        
        if self.timed_out:
            time_passed = self.timeout
            time_passed += self.receiver.sim_transport_time(payload_size)
            self.time_passed = (0, time_passed)
            self.exception = SimTimeoutError("Timeout")
        elif self.corrupt_response:
            time_passed = self.receiver.sim_adjust_time(time_passed)
            self.time_passed = (time_passed, self.receiver.sim_transport_time(payload_size))
            self.exception = SimCorruptResponseError("Corrupt response")
        else:
            response_size = len(self.response.encode() + b'+' + self.enc_response_data)
            self.time_passed = (
                self.receiver.sim_adjust_time(time_passed),
                self.receiver.sim_transport_time(payload_size) + self.receiver.sim_transport_time(response_size)
            )
        
        