import json
import copy

class Report:
    def __init__(self, entries:list = []):
        self.entries = []
        self.encrypted_data = None
        self.is_valid = True # This is a flag that can be set to False to simulate malicious behavior
        self.is_correct = True # This is a flag that can be set to False to simulate malicious behavior
        
        for entry in entries:
            self.append(entry)
    
    def to_json(self):
        return json.dumps(self.entries)
    
    @classmethod
    def from_json(cls, json_str:str):
        return cls(json.loads(json_str))
    
    def copy(self):
        return copy.deepcopy(self)
    
    def append(self, entry:int):
        if not isinstance(entry, int):
            raise ValueError("Entry must be a int")
        self.entries.append(entry)
    
    def negate(self):
        return Report([-entry for entry in self.entries])
    
    @classmethod
    def sum(cls, report_list:list):
        if not all(isinstance(report, Report) for report in report_list):
            raise ValueError("All entries must be of type Report")
        if not all(len(report) == len(report_list[0]) for report in report_list):
            raise ValueError("All reports must have the same number of entries")
        return Report([sum(entries) for entries in zip(*[report.entries for report in report_list])])
    
    def __add__(self, other):
        if not isinstance(other, Report):
            raise ValueError("Can only add Report to Report")
        if len(self.entries) != len(other.entries):
            raise ValueError("Reports must have the same number of entries")
        new_entries = [self.entries[i] + other.entries[i] for i in range(len(self.entries))]
        return Report(new_entries)
    
    def __sub__(self, other):
        if not isinstance(other, Report):
            raise ValueError("Can only subtract Report from Report")
        if len(self.entries) != len(other.entries):
            raise ValueError("Reports must have the same number of entries")
        new_entries = [self.entries[i] - other.entries[i] for i in range(len(self.entries))]
        return Report(new_entries)
    
    def __len__(self):
        return len(self.entries)
    
    def __getitem__(self, key):
        return self.entries[key]
    
    def __setitem__(self, key, value):
        self.entries[key] = value
    
    def __iter__(self):
        return iter(self.entries)
    
    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Report):
            return False
        return self.entries == value.entries
    
    def __str__(self):
        return str(self.entries)

if __name__ == "__main__":
    test_report = Report([1,2,3])
    test_report.append(4)
    test_report[0] = 5
    print(test_report[0])
    for entry in test_report:
        print(entry)
    print(sum(test_report))

    test_report = Report([1,2,3])
    test_report_2 = Report([4,5,6])

    print(test_report + test_report_2)
    print(test_report - test_report_2)
    print(Report(i for i in range(10)))