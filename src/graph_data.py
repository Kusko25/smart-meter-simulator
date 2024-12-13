from Simulator.director import Director, InteractiveNoiseDirector, HomomorphicMultiPartyDirector
from Simulator.report import Report
import pandas as pd
from random import choice, sample
from pathlib import Path
import seaborn as sns
import matplotlib.pyplot as plt

def gather_data():
    csv_path = Path(__file__).resolve().parent / Path("Datasets/Smart meters in London/data/processed.csv")
    if not csv_path.exists():
        print("Didn't find the dataset. Full path:", csv_path.resolve())

    # LCLid,date,00:00,01:00,02:00,03:00,04:00,05:00,06:00,07:00,08:00,09:00,10:00,11:00,12:00,13:00,14:00,15:00,16:00,17:00,18:00,19:00,20:00,21:00,22:00,23:00
    # MAC000002,2012-10-12,0,0,0,0,0,0,0,0,0,0,0,286,919,354,290,288,291,847,423,1413,441,535,595,559
    input_data = pd.read_csv(csv_path)

    # Look at how many entries we have for each date
    step = input_data.groupby('date').size()
    # We will use the date with the most entries
    date = step.idxmax()
    # Get all the entries for that date
    data = input_data[input_data['date'] == date]
    # Results in 993 entries, pad that to 1000 through row duplication
    padding = data.sample(7)
    # Rename the LCLid entries to be unique
    padding['LCLid'] = [f'DUP00000{i}' for i in range(1, 8)]
    # Append the padding to the data
    data = pd.concat([data, padding])
    # Shuffle the data
    data = data.sample(frac=1)
    # Reset the index
    data = data.reset_index(drop=True)

    sp_proc = (50,120)
    sp_comm = (10,1000)

    runs = [
        [sp_proc[0], sum(sp_comm) // 2],
        [sp_proc[1], sum(sp_comm) // 2],
        [sum(sp_proc) // 2, sp_comm[0]],
        [sum(sp_proc) // 2, sp_comm[1]],
    ]
    # sp_proc = (50,85,120)
    # sp_comm = (10,500,1000)

    # runs = []
    # for proc in sp_proc:
    #     for comm in sp_comm:
    #         runs.append([proc, comm])


    output_df = pd.DataFrame(columns=["method","processor_speed", "communication_speed", "batch_size", "total_time", "processing_time", "communication_time"])
    for run in runs:
        for batch_size in range(10, 210, 10):
            sm_list = []
            for i in range(batch_size):
                sm_list.append({
                    "processor_speed": run[0],
                    "communication_speed": run[1],
                    "consumer_data": Report(int(x) for x in data.iloc[i, 2:]),
                    "typical_data_sum": int(data.iloc[i, 2:].sum())
                })

            director = Director.factory(
                    smart_meters=sm_list,
            )
            director.run()
            output_df.loc[len(output_df.index)] = [
                "Ring Aggregation",
                run[0],
                run[1],
                batch_size,
                director.results["total_time"],
                director.results["sm_processing_time"],
                director.results["communication_time"],
            ]
            
            sm_list = []
            for i in range(batch_size):
                sm_list.append({
                    "processor_speed": run[0],
                    "communication_speed": run[1],
                    "consumer_data": Report(int(x) for x in data.iloc[i, 2:]),
                    "typical_data_sum": int(data.iloc[i, 2:].sum())
                })
            
            director = InteractiveNoiseDirector.factory(
                smart_meters=sm_list,
                privacy_parameter=0.1,
            )
            director.run()
            output_df.loc[len(output_df.index)] = [
                "Interactive Noise",
                run[0],
                run[1],
                batch_size,
                director.results["total_time"],
                director.results["sm_processing_time"],
                director.results["communication_time"],
            ]
            
            sm_list = []
            for i in range(batch_size):
                sm_list.append({
                    "processor_speed": run[0],
                    "communication_speed": run[1],
                    "consumer_data": Report(int(x) for x in data.iloc[i, 2:]),
                    "typical_data_sum": int(data.iloc[i, 2:].sum())
                })
            
            director = HomomorphicMultiPartyDirector.factory(
                smart_meters=sm_list,
            )
            director.run()
            output_df.loc[len(output_df.index)] = [
                "Homomorphic Encryption",
                run[0],
                run[1],
                batch_size,
                director.results["total_time"],
                director.results["sm_processing_time"],
                director.results["communication_time"],
            ]

    output_df.to_csv("output10_10_200_10_step.csv", index=False)
    print(output_df)

def plot_data():
    path_csv = Path(__file__).resolve().parent / Path("output10_10_200_10_step.csv")
    x_batchsize = range(10, 210, 10)
    if not path_csv.exists():
        print("Didn't find the output file. Full path:", path_csv.resolve())
        return
    df = pd.read_csv(path_csv)
    sns.set_theme()
    sns.set_context("paper")
    
    def interval_plot(x, lowers, uppers, color, label):
        plt.plot(x, lowers, color=color)
        plt.plot(x, uppers, color=color)
        plt.plot(x, lowers, 's', color=color, label=label[0])
        plt.plot(x, uppers, 'o', color=color, label=label[1])
        plt.fill_between(x, lowers, uppers, color=color, alpha=0.2)
    
    # Variable Processor Speed
    # Pick the entries with communication speed 505
    df_proc = df[df["communication_speed"] == 505]
    y_proc_low = 50
    y_proc_high = 120
    colors = ["blue", "orange", "green"]
    for i,method in enumerate(df["method"].unique()):
        df_method = df_proc[df_proc["method"] == method]
        lower = df_method[df_method["processor_speed"] == y_proc_low]
        upper = df_method[df_method["processor_speed"] == y_proc_high]
        # Sort lower and upper by batch size
        lower = lower.sort_values("batch_size")
        upper = upper.sort_values("batch_size")
        interval_plot(x_batchsize, lower["total_time"], upper["total_time"], colors[i], [f"{method} ({y_proc_low} MHz)", f"{method} ({y_proc_high} MHz)"])
    plt.xlabel("Batch Size")
    plt.ylabel("Total Time (s)")
    plt.title("Total Time vs Batch Size for Variable Processor Speed")
    plt.legend()
    # Name the file
    plt.savefig("total_time_vs_batchsize_proc_1000.png")
    plt.show()
    # Clear the plot
    plt.clf()
    
    # Variable Communication Speed
    df_comm = df[df["processor_speed"] == 85]
    y_comm_low = 10
    y_comm_high = 1000
    colors = ["blue", "orange", "green"]
    for i,method in enumerate(df["method"].unique()):
        df_method = df_comm[df_comm["method"] == method]
        lower = df_method[df_method["communication_speed"] == y_comm_low]
        upper = df_method[df_method["communication_speed"] == y_comm_high]
        # Sort lower and upper by batch size
        lower = lower.sort_values("batch_size")
        upper = upper.sort_values("batch_size")
        interval_plot(x_batchsize, lower["total_time"], upper["total_time"], colors[i], [f"{method} ({y_comm_low} kB/s)", f"{method} ({y_comm_high} kB/s)"])
    plt.xlabel("Batch Size")
    plt.ylabel("Total Time (s)")
    plt.title("Total Time vs Batch Size for Variable Communication Speed")
    plt.legend()
    # Name the file
    plt.savefig("total_time_vs_batchsize_comm_1000.png")
    plt.show()
    # Clear the plot
    plt.clf()

def latex_table():
    path_csv = Path(__file__).resolve().parent / Path("output10_100_200_3x3.csv")
    if not path_csv.exists():
        print("Didn't find the output file. Full path:", path_csv.resolve())
        return
    df = pd.read_csv(path_csv)
    df = df.groupby(["processor_speed","communication_speed","method","batch_size"]).mean().reset_index()
    new_headers = ["Processor Speed (MHz)", "Communication Speed (kB/s)", "Method", "Batch Size", "Total Time (s)", "Processing Time (s)", "Communication Time (s)"]
    df.columns = new_headers
    output_txt_file = Path(__file__).resolve().parent / Path("output10_100_200_3x3.txt")
    output_txt_file.write_text(df.to_latex(index=False, float_format="%.2f"))

# gather_data()
plot_data()
# latex_table()