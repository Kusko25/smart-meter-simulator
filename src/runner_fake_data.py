from Simulator.director import Director
from Simulator.report import Report
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from random import choice, shuffle
from pathlib import Path


base_path = Path(__file__).resolve().parent / "Datasets/Smart meters in London"
csv_path = base_path / "../../fake_data_results.csv"
csv_path_fp = base_path / "../../fake_data_results_fp.csv"
fig_path_error = base_path / "../../fake_data_results.png"
fig_path_fp = base_path / "../../fake_data_results_fp_var.png"

def gather_data():
    # LCLid,date,00:00,01:00,02:00,03:00,04:00,05:00,06:00,07:00,08:00,09:00,10:00,11:00,12:00,13:00,14:00,15:00,16:00,17:00,18:00,19:00,20:00,21:00,22:00,23:00
    # MAC000002,2012-10-12,0,0,0,0,0,0,0,0,0,0,0,286,919,354,290,288,291,847,423,1413,441,535,595,559
    input_data = pd.read_csv(base_path / "data/sm_data_manipulation_test.csv")
    threshold_data = pd.read_csv(base_path / "data/boxplot_data.csv", index_col="Acorn")
    value_columns = [f'{i:02}:00' for i in range(0,24)]

    out_df = pd.DataFrame(columns=[
        "n_smart_meters",
        "n_malicious",
        "false_positives",
        "true_positives",
        "false_negatives",
        "relative_error",
        "threshold_method",
    ])

    N_SMART_METERS = 200
    for threshold_id in ["cutoff", "max"]:
        for j in range(1,21):
            P_MALICIOUS = j * 0.01

            run_data = input_data.sample(N_SMART_METERS + 2)
            malicious = [True]*(int(N_SMART_METERS * P_MALICIOUS)) + [False]*(N_SMART_METERS - int(N_SMART_METERS * P_MALICIOUS))
            shuffle(malicious)
            run_data['malicious'] = malicious + [False, False]
            sm_list = []
            for i in range(N_SMART_METERS):
                consumer_data = Report(int(x) for x in run_data.iloc[i][value_columns])
                acorn = run_data.iloc[i]["Acorn"]
                threshold = threshold_data.loc[acorn, threshold_id]
                threshold = int(threshold) + 1
                sm_list.append({
                    "processor_speed": choice([25, 50, 75, 100]),
                    "communication_speed": choice([10, 100, 1000, 10000]),
                    "consumer_data": consumer_data,
                    "typical_data_sum": threshold,
                })
                if run_data.iloc[i]["malicious"]:
                    sm_list[-1]["malicious_type"] = "manipulate_report"
                    print(f"SmartMeter {i} is malicious and will {sm_list[-1]['malicious_type']}")

            director = Director.factory(
                smart_meters=sm_list,
            )

            director.run()
            # "n_smart_meters",
            # "n_malicious",
            # "false_positives",
            # "true_positives",
            # "false_negatives",
            # "relative_error",
            
            out_df.loc[len(out_df)] = [
                N_SMART_METERS,
                director.results["n_malicous_smart_meters"],
                director.results["n_eliminated_smart_meters"] - (director.results["n_malicous_smart_meters"] - director.results["n_uncaught_malicious_smart_meters"]) -2,
                director.results["n_malicous_smart_meters"] - director.results["n_uncaught_malicious_smart_meters"],
                director.results["n_uncaught_malicious_smart_meters"],
                director.results["error_relative"],
                threshold_id
            ]
    out_df.to_csv(csv_path)
    print(out_df)

def plot_data():
    data = pd.read_csv(csv_path)
    data["relative_error"] = data["relative_error"] * 100
    data["relative_error"] = data["relative_error"].round(2)
    
    # Drop rows with n_malicious > 20
    data = data[data["n_malicious"] <= 20]
    
    sns.set_theme()
    sns.set_context("paper")
    
    fig, ax1 = plt.subplots()
    
    for method,label in zip(["cutoff", "max"], ["Strict", "Permissive"]):
        data_method = data[data["threshold_method"] == method]
        sns.lineplot(data=data_method, x="n_malicious", y="false_positives", ax=ax1, alpha=0.5)
        sns.scatterplot(data=data_method, x="n_malicious", y="false_positives", ax=ax1, label=label)
    ax1.set_xlabel("Number of Malicious Smart Meters (Total: 200)")
    ax1.set_ylabel("False Positives")
    plt.savefig(fig_path_fp)
    
    fig, ax1 = plt.subplots()
    
    for method,label in zip(["cutoff", "max"], ["Strict", "Permissive"]):
        data_method = data[data["threshold_method"] == method]
        sns.lineplot(data=data_method, x="n_malicious", y="relative_error", ax=ax1, alpha=0.5)
        sns.scatterplot(data=data_method, x="n_malicious", y="relative_error", ax=ax1, label=label)
    ax1.set_xlabel("Number of Malicious Smart Meters (Total: 200)")
    ax1.set_ylabel("Relative Error (%)")
    plt.savefig(fig_path_error)

def gather_data_fp():
    # LCLid,date,00:00,01:00,02:00,03:00,04:00,05:00,06:00,07:00,08:00,09:00,10:00,11:00,12:00,13:00,14:00,15:00,16:00,17:00,18:00,19:00,20:00,21:00,22:00,23:00
    # MAC000002,2012-10-12,0,0,0,0,0,0,0,0,0,0,0,286,919,354,290,288,291,847,423,1413,441,535,595,559
    input_data = pd.read_csv(base_path / "data/sm_data_manipulation_test.csv")
    threshold_data = pd.read_csv(base_path / "data/boxplot_data.csv", index_col="Acorn")
    value_columns = [f'{i:02}:00' for i in range(0,24)]

    out_df = pd.DataFrame(columns=[
        "n_smart_meters",
        "false_positives",
        "threshold_method",
    ])

    N_SMART_METERS = 200
    for threshold_id in ["cutoff", "max"]:
        for _ in range(100): # Repeat 5 times to average over randomness
            run_data = input_data.sample(N_SMART_METERS + 2)
            sm_list = []
            for i in range(N_SMART_METERS):
                consumer_data = Report(int(x) for x in run_data.iloc[i][value_columns])
                acorn = run_data.iloc[i]["Acorn"]
                threshold = threshold_data.loc[acorn, threshold_id]
                threshold = int(threshold) + 1
                sm_list.append({
                    "processor_speed": choice([25, 50, 75, 100]),
                    "communication_speed": choice([10, 100, 1000, 10000]),
                    "consumer_data": consumer_data,
                    "typical_data_sum": threshold,
                    "fake_keys": True,
                })

            director = Director.factory(
                smart_meters=sm_list,
            )

            director.run()
            # "n_smart_meters",
            # "n_malicious",
            # "false_positives",
            # "true_positives",
            # "false_negatives",
            # "relative_error",
            
            out_df.loc[len(out_df)] = [
                N_SMART_METERS,
                director.results["n_eliminated_smart_meters"] - (director.results["n_malicous_smart_meters"] - director.results["n_uncaught_malicious_smart_meters"]) -2,
                threshold_id
            ]
    # Average entries where n_malicious and threshold_method are the same
    out_df.to_csv(csv_path_fp)
    print(out_df)

def plot_data_fp():
    data = pd.read_csv(csv_path_fp)
    
    sns.set_theme()
    sns.set_context("paper")
    
    fig, ax1 = plt.subplots()
    
    # for method,label in zip(["threshold_hard", "threshold_soft"], ["Strict", "Permissive"]):
    #     data_method = data[data["threshold_method"] == method]
    #     sns.boxplot(data=data_method, x="false_positives", ax=ax1, label=label)
    data["Threshold Method"] = data["threshold_method"].apply(lambda x: "Strict" if x == "cutoff" else "Permissive")
    data["False Positives"] = data["false_positives"] / data["n_smart_meters"]
    sns.boxplot(data=data, x="False Positives", hue="Threshold Method", ax=ax1)
    # Format x-axis as percentage
    vals = ax1.get_xticks()
    ax1.set_xticklabels(['{:,.0%}'.format(x) for x in vals])
    ax1.set_xlabel("False Positive Rate")
    plt.savefig(fig_path_fp)
    
    fig, ax1 = plt.subplots()

# gather_data()
# plot_data()
# gather_data_fp()
plot_data_fp()