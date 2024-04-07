import pandas as pd
import matplotlib.pyplot as plt
import sys

def main(error_logs):
    df = pd.read_csv(error_logs, header=None)
    df.columns = ['file', 'attack_type', 'timestamp', 'uri', 'client', 'pid', 'referer']

    # Filtering out rows with a dash for 'timestamp'
    df = df[df['timestamp'] != '-']

    # Convert 'timestamp' to datetime, coercing errors to NaT
    df['timestamp'] = pd.to_datetime(df['timestamp'].str.replace('timestamp:', ''), errors='coerce')

    # Drop rows where 'timestamp' is NaT (not a time)
    df = df.dropna(subset=['timestamp'])

    # Count occurrences of each attack type per hour
    df.set_index('timestamp', inplace=True)
    hourly_attack_counts = df.groupby([pd.Grouper(freq='H'), 'attack_type']).size().unstack(fill_value=0)

    # Plotting
    plt.figure(figsize=(15, 8))

    # Plot for each attack type
    for attack_type in hourly_attack_counts:
        plt.plot(hourly_attack_counts.index, hourly_attack_counts[attack_type], label=attack_type)

    plt.xlabel('Timestamp')
    plt.ylabel('Number of events')
    plt.title('Malicious events Over Time')
    plt.legend(title='Event Type')

    # Configure x-axis with date format
    plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y-%m-%d %H:%M'))
    plt.xticks(rotation=90)

    plt.tight_layout()
    plt.savefig('events_errors_line_plot.png')

if __name__ == "__main__":
    # Check if the correct number of arguments are passed
    if len(sys.argv) != 1:
        print("Usage: python error_logs_graph.py <csv file - error_logs>")
        sys.exit(1)

    error_logs = sys.argv[1]
    main(error_logs)
