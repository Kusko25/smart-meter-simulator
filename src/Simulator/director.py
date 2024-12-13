import json
import time
import datetime
import random

from pathlib import Path
import seaborn as sns

try:
    import openfhe
except Exception:
    openfhe = None

from Simulator.exceptions import SimulationError, SimTimeoutError, SimCorruptResponseError
from Simulator.communication import Communication
from Simulator.smart_meter import SmartMeter, InteractiveNoiseSmartMeter, HomomorphicMultiPartySmartMeter
from Simulator.report import Report
from Simulator.globals import (
    N_REPORT_ENTRIES,
    TIMEOUT,
    PRINT_LOGS
)
from typing import List

class Director:
    def __init__(
        self, 
    ):
        self.all_meters = [] # List of SmartMeter objects in order
        self.meter_list = [] # List of SmartMeter objects in order
        self.run_id = None
        self.commands_sent = None
        self.initial_fake_data = None
        self.results = None
        
        self.logs = []
        self.comms_history:List[Communication] = []
    
    @classmethod
    def factory(
        cls, 
        smart_meters,
        smart_meter_type=SmartMeter
    ):
        """This method is used to create a new instance of the class, before simulation starts"""
        obj = cls()
        obj.run_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        for i,smart_meter in enumerate(smart_meters):
            smart_meter["sim_id"] = obj.run_id + "-" + str(i)
            obj.all_meters.append(smart_meter_type.factory(**smart_meter))
        obj.meter_list = obj.all_meters.copy()
        obj.commands_sent = 0
        return obj
    
    @property
    def time_passed(self):
        batches = dict()
        for comm in self.comms_history:
            if comm.batch_id:
                if comm.batch_id in batches:
                    batches[comm.batch_id].append(comm)
                else:
                    batches[comm.batch_id] = [comm]
        time_sum = (0.0, 0.0)
        for comm in self.comms_history:
            if comm.batch_id:
                continue
            time_sum = (time_sum[0]+comm.time_passed[0], time_sum[1]+comm.time_passed[1])
        for batch in batches:
            max_time = (0,0)
            for comm in batches[batch]:
                if sum(comm.time_passed) > sum(max_time):
                    max_time = comm.time_passed
            time_sum = (time_sum[0]+max_time[0], time_sum[1]+max_time[1])
        return time_sum
    
    def log(self, message, data=None, level="info"):
        self.logs.append({
            "message": message,
            "data": data,
            "time": time.time(),
            "sim_id": self.run_id,
            "level": level
        })
        if PRINT_LOGS:
            print(f"[{self.run_id}] {time.time()} {level}: {message}")
    
    def error(self, message, exception=None, data=None):
        self.log(message, data=data, level="error")
        self.logs[-1]["exception"] = exception
    
    def warning(self, message, data=None):
        self.log(message, data=data, level="warning")

    def dump_logs(self):
        logs = []
        for log in self.logs:
            log['type'] = 'Director'
            logs.append(log)
        for smart_meter in self.meter_list:
            for log in smart_meter.logs:
                log['type'] = 'SmartMeter'
                logs.append(log)
        
        logs = sorted(logs, key=lambda x: x['time'])
        log_file = Path("runs/" + self.run_id + "/logs.json")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, 'w') as f:
            f.write(json.dumps(logs, indent=4))
        log_file = Path("runs/" + self.run_id + "/logs.txt")
        with open(log_file, 'w') as f:
            for log in logs:
                f.write(f"{log['time']} {log['type']} {log['level']}: {log['message']}\n")
    
    def dump_results(self, result):        
        result_file = Path("runs/" + self.run_id + "/results.json")
        result_file.parent.mkdir(parents=True, exist_ok=True)
        with open(result_file, 'w') as f:
            f.write(json.dumps(result, indent=4))

        graph = sns.lineplot(result['final_report'])
        graph.set_title(f"Final Report of Simulation {self.run_id}")
        graph.set_xlabel("Hour")
        graph.set_ylabel("Consumption in Wh")
        graph.get_figure().savefig("runs/" + self.run_id + "/final_report.png")
    
    def send_command(
        self, 
        message:str, 
        target:SmartMeter, 
        message_data=None,
        enc_message_data:bytes=b"", 
        timeout=TIMEOUT,
        parallel_batch=None
        ) -> Communication:
        
        assert not message_data or enc_message_data, "enc_message_data is needed when message_data is provided"
        if enc_message_data and not isinstance(enc_message_data,bytes):
            raise TypeError("enc_message_data must be of type bytes")
        
        comm = Communication()
        comm.message = message
        comm.message_data = message_data
        comm.enc_message_data = enc_message_data
        comm.receiver = target
        comm.sender = self
        comm.timeout = timeout
        comm.batch_id = parallel_batch
        comm.send()
        self.comms_history.append(comm)
        return comm
    
    # Commands
    def cmd_send_symmetric_key(self, target_sm, public_key, batch=None):
        # Instruct target_sm to encrypt its symmetric key with the public_key
        # and send it back
        comm = self.send_command(
            target=target_sm,
            message="send_symmetric_key",
            message_data=public_key,
            enc_message_data=b"b"* public_key.__sizeof__(),
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while sending symmetric key", {
                "target_sm": target_sm.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while sending symmetric key", {
                "target_sm": target_sm.sim_id
            })
            raise e
        
        return comm
    
    def cmd_receive_report(self, target_sm, report, encryption_key, slot, batch=None):
        # Instruct target_sm to receive a report and decrypt it
        report = report.copy()
        message_data={
            "report": report,
            "encryption_key": encryption_key,
            "slot": slot
        }
        comm = self.send_command(
            target=target_sm,
            message="receive_report",
            message_data=message_data,
            enc_message_data=b"b"* message_data.__sizeof__(),
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while receiving report", {
                "target_sm": target_sm.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while receiving report", {
                "target_sm": target_sm.sim_id
            })
            raise e
        
        if comm.response != "ok":
            self.warning("SmartMeter failed to receive report", {
                "target_sm": target_sm.sim_id
            })
            raise SimulationError("SmartMeter failed to receive report")
        
        return comm
    
    def cmd_prepare_report(self, smart_meter:SmartMeter, batch=None):
        # Instruct smart_meter to prepare a report
        comm = self.send_command(
            target=smart_meter,
            message="prepare_report",
            message_data=None,
            enc_message_data=b"",
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while preparing report", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while preparing report", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        return comm
    
    def cmd_compare_reports(self, smart_meter:SmartMeter, compare_data, batch=None):
        comm = self.send_command(
            target=smart_meter,
            message="compare_reports",
            message_data=compare_data,
            enc_message_data=b"b"* compare_data.__sizeof__(),
            parallel_batch=batch
        )
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while comparing reports", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while comparing reports", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        if comm.response != "ok":
            self.warning("SmartMeter failed to compare reports", {
                "smart_meter": smart_meter.sim_id
            })
            raise SimulationError("SmartMeter failed to compare reports")
        
        return comm
    
    def cmd_initialize(self, smart_meter:SmartMeter, id:int, batch=None):
        message_data = {
            "id": id
        }
        comm = self.send_command(
            target=smart_meter,
            message="initialize",
            message_data=message_data,
            enc_message_data=b"b"* message_data.__sizeof__(),
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        return comm
    
    def send_report(self,source:SmartMeter, target:SmartMeter, slot:str):
        # Key for target
        try:
            resp = self.cmd_send_symmetric_key(source, target.public_key)
            target_key = resp.response_data
        except SimulationError:
            self.remove_smart_meter(source)
            return False
        # Report for target
        try:
            resp = self.cmd_receive_report(target, source.report, target_key, slot)
        except SimulationError:
            # Either sm_1 bad or smart_meter bad. Remove both
            self.remove_smart_meter(source)
            self.remove_smart_meter(target)
            return False
        
        return True
    
    def remove_smart_meter(self, smart_meter:SmartMeter):
        if smart_meter.is_dummy:
            return
        if smart_meter.is_cool:
            return
        if len(self.meter_list) <= 10:
            self.error("SmartMeter ring is too small")
            raise SimulationError("SmartMeter ring is too small")
        self.log(f"Removing SmartMeter {smart_meter.sim_id}", {
            "sim_id": smart_meter.sim_id,
            "id": smart_meter.id
        })
        self.meter_list = [sm for sm in self.meter_list if sm.sim_id != smart_meter.sim_id]
    
    def add_time(self, time:tuple):
        raise DeprecationWarning("add_time")
        self.time_passed = (self.time_passed[0] + time[0], self.time_passed[1] + time[1])
    
    def start_of_ring(self):
        # Because smart meters are not supposed to know their position in the ring
        # we insert two fake smart meters at the start of the ring
        
        # consumer_data_1 = Report([random.randint(0,100) for i in range(N_REPORT_ENTRIES)])
        # consumer_data_2 = Report([random.randint(0,100) for i in range(N_REPORT_ENTRIES)])
        consumer_data_1 = Report([10 for i in range(N_REPORT_ENTRIES)])
        consumer_data_2 = Report([10 for i in range(N_REPORT_ENTRIES)])
        
        dummy_1 = SmartMeter.factory(
            consumer_data=consumer_data_1,
            typical_data_sum=sum(consumer_data_1),
            sim_id="dummy-1",
            is_dummy=True
        )
        self.cmd_initialize(dummy_1, -2)
        dummy_2 = SmartMeter.factory(
            consumer_data=consumer_data_2,
            typical_data_sum=sum(consumer_data_1),
            sim_id="dummy-2",
            is_dummy=True
        )
        self.cmd_initialize(dummy_2, -1)
        
        # Prepare Initial Fake Data
        self.initial_fake_data = Report(
            random.randint(0, 2**30)
            for i in range(N_REPORT_ENTRIES)
        )
        
        self.cmd_receive_report(dummy_1, self.initial_fake_data, None, "previous")
        self.cmd_prepare_report(dummy_1)
        self.send_report(dummy_1, dummy_2, "previous")
        self.cmd_prepare_report(dummy_2)
        
        self.meter_list = [dummy_1, dummy_2] + self.meter_list
        
        while True:
            # We need to keep going until we confirm sm_1 is cool
            # That is, sm_2 has successfully passed its verification
            sm_1 = self.meter_list[2]
            sm_2 = self.meter_list[3]
            sm_3 = self.meter_list[4]
            
            # sm_1 expects dummy_1 data to verify dummy_2
            if not self.send_report(dummy_1, sm_1, "verifier"):
                continue
            
            # sm_1 receives dummy_2 report
            if not self.send_report(dummy_2, sm_1, "previous"):
                continue
            
            # sm_1 compares dummy_1 and dummy_2 reports
            try:
                self.cmd_compare_reports(sm_1, dummy_2.typical_data_sum)
            except SimulationError:
                # We know dummies are good, so sm_1 is bad
                self.remove_smart_meter(sm_1)
                continue
            
            # sm_1 prepares its report
            try:
                self.cmd_prepare_report(sm_1)
            except SimulationError:
                self.remove_smart_meter(sm_1)
                continue
            
            # sm_2 expects dummy_2 data to verify sm_1
            if not self.send_report(dummy_2, sm_2, "verifier"):
                continue
            
            # sm_2 receives sm_1 report
            if not self.send_report(sm_1, sm_2, "previous"):
                continue
            
            # sm_2 compares dummy_2 and sm_1 reports
            try:
                self.cmd_compare_reports(sm_2, sm_1.typical_data_sum)
            except SimulationError:
                # sm_1 or sm_2 is bad
                self.remove_smart_meter(sm_1)
                self.remove_smart_meter(sm_2)
                continue
            
            # sm_2 prepares its report
            try:
                self.cmd_prepare_report(sm_2)
            except SimulationError:
                self.remove_smart_meter(sm_2)
                continue
            
            # sm_3 expects sm_1 data to verify sm_2
            if not self.send_report(sm_1, sm_3, "verifier"):
                continue
            
            # sm_3 receives sm_2 report
            if not self.send_report(sm_2, sm_3, "previous"):
                continue
            
            # sm_3 compares sm_1 and sm_2 reports
            try:
                self.cmd_compare_reports(sm_3, sm_2.typical_data_sum)
            except SimulationError:
                # sm_1 or sm_2 or sm_3 is bad
                self.remove_smart_meter(sm_1)
                self.remove_smart_meter(sm_2)
                self.remove_smart_meter(sm_3)
                continue
            
            # sm_1 is now confirmed to be good and we can enter the main loop
            sm_1.is_cool = True
            break
    
    def end_of_ring(self):
        end_dummy = SmartMeter.factory(
            sim_id="dummy-3",
            is_dummy=True
        )
        self.cmd_initialize(end_dummy, len(self.all_meters))
        
        while True:
            while not self.meter_list[-1].is_cool:
                self.meter_list = self.meter_list[:-1]
            sm_last = self.meter_list[-1]
            try:
                resp = self.cmd_send_symmetric_key(sm_last, end_dummy.public_key)
                sym_key = resp.response_data
            except SimulationError:
                self.remove_smart_meter(sm_last)
                continue
            try:
                resp = self.cmd_receive_report(end_dummy, sm_last.report, sym_key, "previous")
            except SimulationError:
                self.remove_smart_meter(sm_last)
                continue
            break
        self.meter_list.append(end_dummy)
    
    def initialize(self):
        batch = Communication.generate_batch_id()
        for i,smart_meter in enumerate(list(self.meter_list)):
            try:
                resp = self.cmd_initialize(smart_meter, i, batch=batch)
            except SimulationError:
                self.remove_smart_meter(smart_meter)
                continue
    
    def run_loop(self, index, was_interrupted=False):
        previous_sm:SmartMeter = self.meter_list[index]
        current_sm:SmartMeter = self.meter_list[index+1]
        next_sm:SmartMeter = self.meter_list[index+2]
        
        if was_interrupted:
            # Something went wrong and SMs were removed
            # We need to retransmit the reports from the last good SM
            last_cool_sm = self.meter_list[index-1]
            
            if not self.send_report(last_cool_sm, previous_sm, "previous"):
                return False
            
            try:
                _ = self.cmd_prepare_report(previous_sm)
            except SimulationError:
                self.remove_smart_meter(previous_sm)
                return False
            
            if not self.send_report(last_cool_sm, current_sm, "verifier"):
                return False
            
            if not self.send_report(previous_sm, current_sm, "previous"):
                return False
            
            try:
                _ = self.cmd_compare_reports(current_sm, previous_sm.typical_data_sum)
            except SimulationError:
                self.remove_smart_meter(previous_sm)
                self.remove_smart_meter(current_sm)
                return False
        
        # Previous sends its report to next
        if not self.send_report(previous_sm, next_sm, "verifier"):
            return False
        
        # Current now has to prepare its report
        try:
            _ = self.cmd_prepare_report(current_sm)
        except SimulationError:
            self.remove_smart_meter(current_sm)
            return False
        
        # Current sends its report to next
        if not self.send_report(current_sm, next_sm, "previous"):
            return False
        
        # Next compares the reports
        try:
            _ = self.cmd_compare_reports(next_sm, current_sm.typical_data_sum)
        except SimulationError:
            # One of the smart meters is bad. Remove all three.
            self.remove_smart_meter(previous_sm)
            self.remove_smart_meter(current_sm)
            self.remove_smart_meter(next_sm)
            return False
        
        # Previous is now confirmed to be good
        previous_sm.is_cool = True
        
        return True
    
    def run(self):
        # Initialize SM ring
        # Initialization happens in parallel, only longest time is taken
        self.initialize()

        # Prepare Initial Fake Data
        self.start_of_ring()
        
        # Main loop
        last_interrupted = False
        while True:
            # We are done when there are three un-cool SmartMeters left
            if self.meter_list[-3].is_cool:
                break
            # Pick first un-cool SmartMeter
            index = 2
            while self.meter_list[index].is_cool:
                index += 1
            last_interrupted = not self.run_loop(index, last_interrupted)
        
        self.end_of_ring()
        
        self.finish()
    
    def prepare_results(self):
        result = dict()
        result['type'] = 'RingAggregation'
        result['final_report'] = self.meter_list[-1].predecessor_report - self.meter_list[1].report
        result['final_report'] = json.loads(result['final_report'].to_json())
        time_passed = self.time_passed
        result['total_time'] = time_passed[0] + time_passed[1]
        result['sm_processing_time'] = time_passed[0]
        result['communication_time'] = time_passed[1]
        result['sequential_comms'] = len([comm for comm in self.comms_history if comm.batch_id == None])
        result['paralell_comms'] = len(set([comm.batch_id for comm in self.comms_history])) - 1
        result['bytes_transferred'] = sum([comm.bytes_transmitted for comm in self.comms_history])
        result['n_smart_meters'] = len(self.all_meters)
        result['n_eliminated_smart_meters'] = len(self.all_meters) - sum(1 for sm in self.meter_list if not sm.is_dummy)
        result['n_malicous_smart_meters'] = len([sm for sm in self.all_meters if sm.malicious_type])
        result['n_uncaught_malicious_smart_meters'] = len([sm for sm in self.meter_list if sm.malicious_type])
        result['n_uncaught_errors'] = len([sm for sm in self.meter_list if sm.report and not sm.report.is_correct])
        
        breakdown = [
            "initialize",
            "compare_reports",
            "prepare_report",
            "receive_report",
            "send_symmetric_key",
        ]
        breakdown = {x:(0.0,0.0,0) for x in breakdown}
        
        for comm in self.comms_history:
            breakdown[comm.message] = (breakdown[comm.message][0]+comm.time_passed[0], breakdown[comm.message][1]+comm.time_passed[1],breakdown[comm.message][2]+1)
                    
        result['breakdown'] = {
            x : f"{breakdown[x]} ({breakdown[x][0]/breakdown[x][2]}, {breakdown[x][1]/breakdown[x][2]})"
            for x in breakdown
        }
        actual_result = None
        for sm in self.meter_list:
            if sm.is_dummy:
                continue
            if actual_result is None:
                actual_result = sm.consumer_data
            else:
                actual_result += sm.consumer_data
        computed_result = self.meter_list[-1].predecessor_report - self.meter_list[1].report
        error = sum(abs(a-c) for a,c in zip(actual_result, computed_result))
        result['error'] = error
        result['error_relative'] = error / sum(actual_result)
        
        self.results = result
        
        return result
    
    def finish(self):
        result = self.prepare_results()
        
        self.log("Simulation finished.")
        self.log(f"Total time: {result['total_time']:.2f}s")
        self.log(f"SM processing time: {result['sm_processing_time']:.2f}s")
        self.log(f"Communication time: {result['communication_time']:.2f}s")
        self.log(f"Number of sequential communications: {result['sequential_comms']}")
        self.log(f"Batches of paralell communications: {result['paralell_comms']}")
        self.log(f"Total amount of bytes transferred: {result['bytes_transferred']}")
        self.log(f"Number of SmartMeters: {result['n_smart_meters']}")
        self.log(f"Eliminated SmartMeters: {result['n_eliminated_smart_meters']}")
        self.log(f"Number of malicious SmartMeters: {result['n_malicous_smart_meters']}")
        self.log(f"Number of uncaught malicious SmartMeters: {result['n_uncaught_malicious_smart_meters']}")
        self.log(f"Uncaught errors: {result['n_uncaught_errors']}")
        self.log(f"Error: {result['error']}")
        if "error_relative" in result:
            self.log(f"Relative Error: {result['error_relative']:0.2%}")
        self.dump_logs()
        self.dump_results(result= result)
        pass

class InteractiveNoiseDirector(Director):
    def __init__(
        self, 
        **kwargs
    ):
        super().__init__(**kwargs)
        self.privacy_parameter = None
        self.leader_masks = None
    
    @classmethod
    def factory(
        cls, 
        smart_meters,
        privacy_parameter:float,
    ):
        obj = super().factory(smart_meters, smart_meter_type=InteractiveNoiseSmartMeter)
        obj.privacy_parameter = int(privacy_parameter * len(obj.meter_list))
        leaders = random.sample(obj.meter_list, obj.privacy_parameter)
        for leader in leaders:
            leader.is_leader = True
        return obj
    
    def cmd_initialize(self, smart_meter: InteractiveNoiseSmartMeter, id: int, batch=None):
        message_data = {
            "id": id,
            "privacy_parameter": self.privacy_parameter,
            "is_leader": smart_meter.is_leader
        }
        comm = self.send_command(
            target=smart_meter,
            message="initialize",
            message_data=message_data,
            enc_message_data=b"b"* message_data.__sizeof__(),
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        return comm
    
    def cmd_get_data(self, smart_meter: InteractiveNoiseSmartMeter, batch=None):
        message_data = [sm.public_key for sm in self.meter_list if sm.is_leader]
        comm = self.send_command(
            target=smart_meter,
            message="send_data",
            message_data=message_data,
            enc_message_data=b"b"* message_data.__sizeof__(),
            parallel_batch=batch
        )
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while getting data", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while getting data", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        return comm
    
    def cmd_get_leader_data(self, smart_meter: InteractiveNoiseSmartMeter, leader_masks: list, batch=None):
        message_data = leader_masks
        comm = self.send_command(
            target=smart_meter,
            message="send_leader_data",
            message_data=message_data,
            enc_message_data=b"b"* message_data.__sizeof__(),
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while getting leader data", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while getting leader data", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        return comm
    
    def initialize(self):
        super().initialize()
    
    def get_data_from_non_leaders(self):
        self.leader_masks = [
            list() for i in range(self.privacy_parameter)
        ]
        
        batch = Communication.generate_batch_id()
        for i,smart_meter in enumerate(list(self.meter_list)):
            if smart_meter.is_leader:
                continue
            try:
                resp = self.cmd_get_data(smart_meter, batch=batch)
            except SimulationError as e:
                raise e
            sm_noised_data = resp.response_data[0]
            smart_meter.noised_data = sm_noised_data
            
            for j,mask in enumerate(resp.response_data[1:]):
                self.leader_masks[j].append(mask)
    
    def get_data_from_leaders(self):
        batch = Communication.generate_batch_id()
        for i,smart_meter in enumerate([sm for sm in self.meter_list if sm.is_leader]):
            try:
                resp = self.cmd_get_leader_data(smart_meter, self.leader_masks[i], batch=batch)
            except SimulationError as e:
                raise e
            
            sm_noised_data = resp.response_data
            smart_meter.noised_data = sm_noised_data
    
    def prepare_results(self):
        result = dict()
        result['type'] = 'InteractiveNoise'
        result['final_report'] = Report.sum([sm.noised_data for sm in self.meter_list])
        result['final_report'] = result['final_report'].entries
        time_passed = self.time_passed
        result['total_time'] = time_passed[0] + time_passed[1]
        result['sm_processing_time'] = time_passed[0]
        result['communication_time'] = time_passed[1]
        result['sequential_comms'] = len([comm for comm in self.comms_history if comm.batch_id == None])
        result['paralell_comms'] = len(set([comm.batch_id for comm in self.comms_history])) - 1
        result['bytes_transferred'] = sum([comm.bytes_transmitted for comm in self.comms_history])
        result['n_smart_meters'] = len(self.all_meters)
        result['n_eliminated_smart_meters'] = len(self.all_meters) - sum(1 for sm in self.meter_list)
        result['n_malicous_smart_meters'] = len([sm for sm in self.all_meters if sm.malicious_type])
        result['n_uncaught_malicious_smart_meters'] = len([sm for sm in self.meter_list if sm.malicious_type])
        result['n_uncaught_errors'] = len([sm for sm in self.meter_list if sm.report and not sm.report.is_correct])
        
        actual_result = None
        for sm in self.meter_list:
            if actual_result is None:
                actual_result = sm.consumer_data
            else:
                actual_result += sm.consumer_data
        computed_result = result['final_report']
        error = sum(abs(a-c) for a,c in zip(actual_result, computed_result))
        result['error'] = error
        self.results = result
        return result
    
    def run(self):
        self.initialize()
        
        self.get_data_from_non_leaders()
        self.get_data_from_leaders()
        
        self.finish()

class HomomorphicMultiPartyDirector(Director):
    def __init__(
        self, 
        **kwargs
    ):
        super().__init__(**kwargs)
        self.cc = None
        self.group_key = None
        self.crypt_total = None
    
    @classmethod
    def factory(
        cls, 
        smart_meters
    ):
        obj = super().factory(smart_meters, smart_meter_type=HomomorphicMultiPartySmartMeter)
        return obj
    
    def cmd_initialize(self, smart_meter:SmartMeter, id:int, previous_key, batch=None):
        message_data = {
            "id": id,
            "cc": self.cc
        }
        if previous_key:
            message_data["previous_key"] = previous_key
        comm = self.send_command(
            target=smart_meter,
            message="initialize",
            message_data=message_data,
            enc_message_data=b"b"* message_data.__sizeof__(),
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        return comm
    
    def cmd_gather_data(self, smart_meter:SmartMeter, batch=None):
        message_data = self.group_key
        comm = self.send_command(
            target=smart_meter,
            message="send_data",
            message_data=message_data,
            enc_message_data=b"b"* message_data.__sizeof__(),
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        return comm

    def cmd_partial_decrypt(self, smart_meter:SmartMeter, ciphertextAdd, first=False, batch=None):
        message_data = {
            "report": ciphertextAdd,
            "mode": "lead" if first else "main"
        }
        comm = self.send_command(
            target=smart_meter,
            message="partial_decrypt",
            message_data=message_data,
            enc_message_data=b"b"* message_data.__sizeof__(),
            parallel_batch=batch
        )
        
        try:
            if comm.exception:
                raise comm.exception
        except SimTimeoutError as e:
            self.error("Timeout while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        except SimCorruptResponseError as e:
            self.error("Corrupt response while initializing", {
                "smart_meter": smart_meter.sim_id
            })
            raise e
        
        return comm
    
    def initialize(self):
        parameters = openfhe.CCParamsBGVRNS()
        # parameters.SetPlaintextModulus(65537)
        # parameters.SetPlaintextModulus(163841)
        parameters.SetPlaintextModulus(557057)
        # parameters.SetPlaintextModulus(163841)
        # parameters.SetPlaintextModulus(163841)

        # NOISE_FLOODING_MULTIPARTY adds extra noise to the ciphertext before decrypting
        # and is most secure mode of threshold FHE for BFV and BGV.
        parameters.SetMultipartyMode(openfhe.NOISE_FLOODING_MULTIPARTY)

        self.cc = openfhe.GenCryptoContext(parameters)
        # Enable Features you wish to use
        self.cc.Enable(openfhe.PKE)
        self.cc.Enable(openfhe.KEYSWITCH)
        self.cc.Enable(openfhe.LEVELEDSHE)
        self.cc.Enable(openfhe.ADVANCEDSHE)
        self.cc.Enable(openfhe.MULTIPARTY)
        
        prev_key = None
        for i,smart_meter in enumerate(list(self.meter_list)):
            resp = self.cmd_initialize(smart_meter, i, prev_key)
            prev_key = resp.response_data
        self.group_key = prev_key
    
    def gather_data(self):
        batch = Communication.generate_batch_id()
        ciphertexts = []
        for i,smart_meter in enumerate(list(self.meter_list)):
            resp = self.cmd_gather_data(smart_meter, batch=batch)
            ciphertexts.append(resp.response_data)
        return ciphertexts
    
    def sum_cipher(self, ciphertexts):
        ciphertextAdd = self.cc.EvalAdd(ciphertexts[0],ciphertexts[1])
        for cipher in ciphertexts[2:]:
            ciphertextAdd = self.cc.EvalAdd(ciphertextAdd,cipher)
        return ciphertextAdd
    
    def decrypt_partials(self, ciphertextAdd):
        batch = Communication.generate_batch_id()
        partialCiphertextVec = []
        for i,smart_meter in enumerate(list(self.meter_list)):
            resp = self.cmd_partial_decrypt(smart_meter, [ciphertextAdd], first=i==0, batch=batch)
            partialCiphertextVec.append(resp.response_data[0])
        return partialCiphertextVec
    
    def get_total(self, partialCiphertextVec):
        plaintextMultipartyNew = self.cc.MultipartyDecryptFusion(partialCiphertextVec)
        plaintextMultipartyNew.SetLength(
            self.cc.MakePackedPlaintext(
                self.meter_list[0].consumer_data.entries
            ).GetLength())
        return plaintextMultipartyNew
    
    def prepare_results(self):
        result = dict()
        result['type'] = 'HomomorphicMultiParty'
        result['final_report'] = self.crypt_total
        result['final_report'] = result['final_report'].entries
        time_passed = self.time_passed
        result['total_time'] = time_passed[0] + time_passed[1]
        result['sm_processing_time'] = time_passed[0]
        result['communication_time'] = time_passed[1]
        result['sequential_comms'] = len([comm for comm in self.comms_history if comm.batch_id == None])
        result['paralell_comms'] = len(set([comm.batch_id for comm in self.comms_history])) - 1
        result['bytes_transferred'] = sum([comm.bytes_transmitted for comm in self.comms_history])
        result['n_smart_meters'] = len(self.all_meters)
        result['n_eliminated_smart_meters'] = len(self.all_meters) - sum(1 for sm in self.meter_list)
        result['n_malicous_smart_meters'] = 0
        result['n_uncaught_malicious_smart_meters'] = 0
        result['n_uncaught_errors'] = len([sm for sm in self.meter_list if sm.report and not sm.report.is_correct])
        
        actual_result = Report.sum([x.consumer_data for x in self.meter_list])
        computed_result = result['final_report']
        error = sum(abs(a-c) for a,c in zip(actual_result, computed_result))
        result['error'] = error
        self.results = result
        return result
    
    def run(self):
        self.initialize()
        ciphertexts = self.gather_data()
        ciphertextAdd = self.sum_cipher(ciphertexts=ciphertexts)
        partialCiphertextVec = self.decrypt_partials(ciphertextAdd=ciphertextAdd)
        self.crypt_total = self.get_total(partialCiphertextVec=partialCiphertextVec)
        self.crypt_total = Report([int(x) for x in str(self.crypt_total)[2:-2].split()[:-1]])
        self.finish()