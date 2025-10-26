# app.py
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import pandas as pd
import sqlite3
from datetime import datetime

# Initialize the Dash app
app = dash.Dash(__name__, title="Real-Time Cyber Incident Dashboard")

# --- Database & Data Retrieval Functions ---

def fetch_incident_data():
    """Fetches all incident data from the SQLite database."""
    conn = sqlite3.connect('cyber_incidents.db')
    query = "SELECT * FROM incidents ORDER BY timestamp DESC"
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# --- Layout Components ---

app.layout = html.Div(style={'backgroundColor': '#f8f9fa', 'padding': '20px'}, children=[
    html.H1("Real-Time Cyber Incident Tracker 🚨", 
            style={'textAlign': 'center', 'color': '#007bff', 'marginBottom': '30px'}),

    # Interval component for periodic updates (simulating real-time)
    dcc.Interval(
        id='interval-component',
        interval=5*1000,  # Update every 5 seconds
        n_intervals=0
    ),

    # Container for all dynamic content
    html.Div(id='live-update-content'),
])

# --- Callbacks for Real-Time Updates ---

@app.callback(Output('live-update-content', 'children'),
              [Input('interval-component', 'n_intervals')])
def update_metrics(n):
    """Callback function to fetch data and update all dashboard components."""
    
    # 1. Fetch Data
    df = fetch_incident_data()
    
    # 2. Key Metrics
    total_incidents = len(df)
    open_incidents = len(df[df['status'] == 'Open'])
    critical_incidents = len(df[df['severity'] == 'CRITICAL'])
    
    # Calculate time since the newest incident (simulating last alert)
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        last_alert_time = (datetime.now() - df['timestamp'].max()).total_seconds() / 60
        last_alert_str = f"{last_alert_time:.1f} min ago"
    else:
        last_alert_str = "N/A"

    # --- Metrics Layout (Flexbox for a responsive look) ---
    metrics_layout = html.Div([
        # Metric Boxes
        html.Div([
            html.Div(f"Total Incidents: {total_incidents}", className='metric-box', style={'backgroundColor': '#007bff', 'color': 'white'}),
            html.Div(f"Open Tickets: {open_incidents}", className='metric-box', style={'backgroundColor': '#dc3545', 'color': 'white'}),
            html.Div(f"CRITICAL Alerts: {critical_incidents}", className='metric-box', style={'backgroundColor': '#ffc107', 'color': 'black'}),
            html.Div(f"Last Alert: {last_alert_str}", className='metric-box', style={'backgroundColor': '#28a745', 'color': 'white'}),
        ], style={'display': 'flex', 'justifyContent': 'space-around', 'marginBottom': '30px'}),

        html.Div(style={'display': 'flex', 'gap': '20px'}, children=[
            # --- Left Column (Charts) ---
            html.Div(style={'flex': 3}, children=[
                # Chart 1: Incidents by Attack Type
                dcc.Graph(
                    id='attack-type-pie',
                    figure=px.pie(
                        df, 
                        names='attack_type', 
                        title='Incident Distribution by Attack Type 📊',
                        hole=.3,
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    ),
                    config={'displayModeBar': False}
                ),
                
                # Chart 2: Incidents by Severity and Status
                dcc.Graph(
                    id='severity-status-bar',
                    figure=px.bar(
                        df.groupby(['severity', 'status']).size().reset_index(name='Count'),
                        x='status', 
                        y='Count', 
                        color='severity', 
                        title='Tickets by Status and Severity 📈',
                        category_orders={"severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                        color_discrete_map={'CRITICAL': '#dc3545', 'HIGH': '#ffc107', 'MEDIUM': '#007bff', 'LOW': '#28a745'}
                    ),
                    config={'displayModeBar': False}
                ),
            ]),

            # --- Right Column (Table) ---
            html.Div(style={'flex': 2, 'overflowY': 'auto', 'maxHeight': '800px'}, children=[
                html.H3("Recent High/Critical Incidents (Last 10)", style={'textAlign': 'center', 'color': '#343a40'}),
                generate_incident_table(df)
            ]),
        ])
    ])

    return metrics_layout

# --- Table Generation Function ---

def generate_incident_table(df):
    """Generates a simple HTML table for the most recent incidents."""
    
    # Filter for High/Critical/Medium and get the 10 most recent
    display_df = df[df['severity'].isin(['CRITICAL', 'HIGH', 'MEDIUM'])].head(10)

    # Style rows based on severity
    def get_row_style(severity):
        if severity == 'CRITICAL':
            return {'backgroundColor': '#f8d7da', 'color': '#721c24'} # Light Red
        elif severity == 'HIGH':
            return {'backgroundColor': '#fff3cd', 'color': '#856404'} # Light Yellow
        elif severity == 'MEDIUM':
            return {'backgroundColor': '#cce5ff', 'color': '#004085'} # Light Blue
        return {'backgroundColor': 'white', 'color': 'black'}

    header = [html.Thead(html.Tr([html.Th(col) for col in ['Time', 'Incident ID', 'Type', 'Severity', 'Status']]))]
    
    body = [
        html.Tr(
            [
                html.Td(datetime.strptime(str(row['timestamp']), '%Y-%m-%d %H:%M:%S.%f').strftime('%H:%M:%S')),
                html.Td(row['incident_id']),
                html.Td(row['attack_type']),
                html.Td(row['severity']),
                html.Td(row['status']),
            ],
            style=get_row_style(row['severity'])
        )
        for index, row in display_df.iterrows()
    ]

    return html.Table(header + [html.Tbody(body)], 
                      style={'width': '100%', 'borderCollapse': 'collapse', 'fontSize': '14px'},
                      className='table table-striped')

# --- Custom CSS Styles (for simplicity, embedded here) ---

app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%séssis!meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"%}
        <title>Real-Time Cyber Incident Tracker</title>
        <style>
            .metric-box {
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                text-align: center;
                font-weight: bold;
                font-size: 1.2em;
                margin: 0 10px;
                flex: 1;
            }
            .table {
                width: 100%;
                border-collapse: collapse;
            }
            .table th, .table td {
                border: 1px solid #dee2e6;
                padding: 8px;
                text-align: left;
            }
            .table th {
                background-color: #e9ecef;
                color: #495057;
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''


# --- Run the application ---
if __name__ == '__main__':
    # NOTE: Run 'python generate_data.py' first to create the database.
    app.run_server(debug=True, host='0.0.0.0', port=8050)