import pandas as pd

def validate_and_prepare_data(data):
    """ 
    Validate and prepare data: check for extra and missing columns 
    compared to those used in model training.
    """

    # data = "/home/parrot/own_cloud_server/captured_traffic.csv"
    # data = pd.read_csv(data)
    # List of columns that were used during model training
    TRAINING_COLUMNS = [
        'dst_port', 'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 
        'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_max', 
        'fwd_pkt_len_min', 'fwd_pkt_len_mean', 'fwd_pkt_len_std', 
        'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean', 
        'bwd_pkt_len_std', 'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 
        'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_tot', 
        'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 
        'bwd_iat_tot', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 
        'bwd_iat_min', 'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 
        'bwd_urg_flags', 'fwd_header_len', 'bwd_header_len', 'fwd_pkts_s', 
        'bwd_pkts_s', 'pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 
        'pkt_len_std', 'pkt_len_var', 'fin_flag_cnt', 'syn_flag_cnt', 
        'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt', 'urg_flag_cnt', 
        'cwe_flag_count', 'ece_flag_cnt', 'down_up_ratio', 'pkt_size_avg', 
        'fwd_seg_size_avg', 'bwd_seg_size_avg', 'fwd_header_len', 
        'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'fwd_blk_rate_avg', 
        'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'bwd_blk_rate_avg', 
        'subflow_fwd_pkts', 'subflow_fwd_byts', 'subflow_bwd_pkts', 
        'subflow_bwd_byts', 'init_fwd_win_byts', 'init_bwd_win_byts', 
        'fwd_act_data_pkts', 'fwd_seg_size_min', 'active_mean', 
        'active_std', 'active_max', 'active_min', 'idle_mean', 
        'idle_std', 'idle_max', 'idle_min', 'Label'
    ]

    # Get the columns from the uploaded CSV file
    csv_columns = data.columns.tolist()

    # Identify extra columns in the uploaded CSV that were not in training
    extra_columns = list(set(csv_columns) - set(TRAINING_COLUMNS))
    
    # Identify missing columns that were in training but are not in the CSV
    missing_columns = list(set(TRAINING_COLUMNS) - set(csv_columns))

    # Display the extra and missing columns
    if extra_columns:
        print(f"Extra columns in uploaded CSV: {extra_columns}")
    if missing_columns:
        print(f"Missing columns in uploaded CSV: {missing_columns}")

    # Remove the extra columns
    data = data.drop(columns=extra_columns, errors='ignore')

    # Add missing columns with default values (e.g., 0)
    for column in missing_columns:
        data[column] = 0  # Or some other default value based on your dataset

    return data


data = validate_and_prepare_data()
print(data)
