import argparse
import json
import os

import dash
import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import pandas as pd
from dash.dependencies import Input, Output

external_stylesheets = [dbc.themes.BOOTSTRAP]

app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

def load_data(path):
    if os.path.isfile(path):
        return pd.read_json(path)
    elif os.path.isdir(path):
        files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith('.json')]
        return pd.concat([pd.read_json(f) for f in files], ignore_index=True)
    else:
        raise ValueError(f"Invalid data path: {path}")

def create_panel(title, panel_type, data_source, **kwargs):
    if panel_type == 'table':
        fields = kwargs.get('fields', [])
        sort_by = kwargs.get('sort_by', fields[0] if fields else None)
        data = data_source[fields].sort_values(by=sort_by, ascending=False)
        return html.Div([
            html.H4(title),
            dbc.Table.from_dataframe(data, striped=True, bordered=True, hover=True, responsive=True)
        ])
    elif panel_type == 'histogram':
        x_field = kwargs.get('x_field')
        bins = kwargs.get('bins', 10)
        figure = px.histogram(data_source, x=x_field, nbins=bins)
        return html.Div([
            html.H4(title),
            dcc.Graph(figure=figure)
        ])
    elif panel_type == 'bar':
        x_field = kwargs.get('x_field')
        y_field = kwargs.get('y_field')  
        figure = px.bar(data_source, x=x_field, y=y_field)
        return html.Div([
            html.H4(title),
            dcc.Graph(figure=figure)
        ])
    elif panel_type == 'line':
        x_field = kwargs.get('x_field')
        y_field = kwargs.get('y_field')
        figure = px.line(data_source, x=x_field, y=y_field)
        return html.Div([
            html.H4(title),
            dcc.Graph(figure=figure)
        ])
                 

def create_layout(config):
    views = []
    for name, view in config['views'].items():
        rows = []
        for _ in range(view['rows']):
            panels = []
            for panel_config in view['panels']:
                data_source_config = config['data_sources'][panel_config['data_source']]
                data_source = load_data(data_source_config['path'])
                panel = create_panel(panel_config['title'], panel_config['type'], data_source, **panel_config)
                panels.append(dbc.Col(panel))
            row = dbc.Row(panels)
            rows.append(row)
        view_layout = html.Div([
            html.H2(view['title']),
            html.Div(rows)
        ])
        views.append(view_layout)
    
    return html.Div(views)

def run_dashboard(config):
    app.layout = create_layout(config)
    app.run_server(debug=True, host=config['server']['host'], port=config['server']['port'])
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/dashboard_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_dashboard(config)