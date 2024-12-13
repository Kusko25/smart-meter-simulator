from Simulator.director import Director, InteractiveNoiseDirector, HomomorphicMultiPartyDirector
from Simulator.report import Report
import pandas as pd
from random import choice, sample
# LCLid,date,00:00,01:00,02:00,03:00,04:00,05:00,06:00,07:00,08:00,09:00,10:00,11:00,12:00,13:00,14:00,15:00,16:00,17:00,18:00,19:00,20:00,21:00,22:00,23:00
# MAC000002,2012-10-12,0,0,0,0,0,0,0,0,0,0,0,286,919,354,290,288,291,847,423,1413,441,535,595,559
input_data = pd.read_csv("Datasets/Smart meters in London/data/processed.csv")

N_SMART_METERS = 200
# Pick a random date with at least 100 readings
# Look at how many entries we have for each date
step = input_data.groupby('date').size()
# Filter out dates with less than 100 entries
step = step[step > N_SMART_METERS]
# Pick a random date from that list
date = step.sample(1).index[0]
# Filter out all entries that are not from that date and pick 100 random entries
input_data = input_data[input_data['date'] == date].sample(N_SMART_METERS)
sm_list = []
for i in range(N_SMART_METERS):
    sm_list.append({
        "processor_speed": choice([25, 50, 75, 100]),
        "communication_speed": choice([10, 100, 1000, 10000]),
        "consumer_data": Report(int(x) for x in input_data.iloc[i, 2:]),
        "typical_data_sum": int(input_data.iloc[i, 2:].sum())
    })

# malicious = sample(range(100), 10)
# for i,action in zip(malicious, ["timeout","corrupt_response","corrupt_report","claim_invalid_report","claim_invalid_verification"]):
#     sm_list[i]["malicious_type"] = action
#     print(f"SmartMeter {i} is malicious and will {action}")

switch = 2
if switch==0:
    director = Director.factory(
        smart_meters=sm_list,
    )
elif switch==1:
    director = InteractiveNoiseDirector.factory(
        smart_meters=sm_list,
        privacy_parameter=0.1,
    )
elif switch==2:
    director = HomomorphicMultiPartyDirector.factory(
        smart_meters=sm_list,
    )

director.run()