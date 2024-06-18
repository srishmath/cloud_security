#!/usr/bin/env python
# coding: utf-8

import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import panel as pn
import matplotlib.pyplot as plt

pn.extension()

# Load the dataset
file_path = r"../data/Dataset_with_cloud_component.csv"  # Use relative path
df = pd.read_csv(file_path)

# Create widgets for user interaction
vendor_search = pn.widgets.AutocompleteInput(name='Search Vendor', options=df['vendor_project'].unique().tolist(), case_sensitive=False)
data_selector = pn.widgets.RadioButtonGroup(name='Select Data Type', options=['Vulnerability', 'Cloud'], button_type='success')

# Define functions to create plots based on user selections
def create_vulnerability_plots(vendor):
    vendor_data = df[df['vendor_project'] == vendor]
    if vendor_data.empty:
        return None
    
    # Bar plot
    severity_counts = vendor_data['severity'].value_counts()
    fig1, ax1 = plt.subplots(figsize=(8, 8))
    severity_counts.plot(kind='bar', color='skyblue', ax=ax1)
    ax1.set_title('Vulnerability Severity Counts for ' + vendor)
    ax1.set_xlabel('Severity Level')
    ax1.set_ylabel('Count')
    ax1.tick_params(axis='x', rotation=0)  # Rotate x-axis labels

    # Time graph
    vendor_data['year'] = pd.to_datetime(vendor_data['pub_date']).dt.year
    yearly_counts = vendor_data['year'].value_counts().sort_index()
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    yearly_counts.plot(marker='o', ax=ax2)
    ax2.set_title('Vulnerability Discovery Over Time for ' + vendor)
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Number of Vulnerabilities Discovered')
    ax2.grid(True)
    ax2.set_xticks(yearly_counts.index)
    ax2.set_xticklabels(yearly_counts.index, rotation=45)
    
    # Pie chart
    attack_vector_counts = vendor_data['vector'].value_counts()
    fig3, ax3 = plt.subplots(figsize=(4, 4))
    ax3.pie(attack_vector_counts, labels=attack_vector_counts.index, autopct='%1.1f%%', startangle=140)
    ax3.set_title('Distribution of Attack Vectors for ' + vendor)
    
    # Stacked bar chart
    cwe_severity_counts = vendor_data.groupby(['cwe', 'severity']).size().unstack(fill_value=0)
    fig4, ax4 = plt.subplots(figsize=(10, 6))
    cwe_severity_counts.plot(kind='bar', stacked=True, ax=ax4)
    ax4.set_title('Vulnerability Counts by CWE Category and Severity for ' + vendor)
    ax4.set_xlabel('CWE Category')
    ax4.set_ylabel('Count')
    ax4.legend(title='Severity')
    
    return [fig1, fig2, fig3, fig4]

def create_cloud_plots(vendor):
    vendor_data = df[df['vendor_project'] == vendor]
    if vendor_data.empty:
        return None
    
    # Plot 1: Severity of Vulnerabilities Across Cloud Components
    severity_counts = vendor_data.groupby(['cloud_component', 'severity']).size().unstack(fill_value=0)    
    fig1, ax1 = plt.subplots(figsize=(10, 8))
    severity_counts.plot(kind='bar', stacked=True, color=['red', 'orange', 'yellow', 'green'], width=0.8, ax=ax1)
    ax1.set_title('Severity of Vulnerabilities Across Cloud Components')
    ax1.set_xlabel('Cloud Component')
    ax1.set_ylabel('Number of Vulnerabilities')
    ax1.set_xticklabels(ax1.get_xticklabels(), rotation=45, ha='right')
    ax1.legend(title='Severity')
    plt.tight_layout()

    # Plot 2: Pie charts for each cloud_component based on vulnerability_category
    grouped_data = vendor_data.groupby(['cloud_component', 'vulnerability_category']).size().unstack(fill_value=0)
    figs = [fig1]

    for component in grouped_data.index:
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.pie(grouped_data.loc[component], labels=grouped_data.columns, autopct='%1.1f%%', startangle=140)
        ax.set_title(f'{vendor.capitalize()} - {component} Vulnerabilities by Category')
        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        figs.append(fig)

    return figs

# Define callback function to update plots based on widget interactions
def update_plots(vendor, data_type):
    if data_type == 'Vulnerability':
        plt_objs = create_vulnerability_plots(vendor)
        if plt_objs:
            bar_plot_pane = pn.pane.Matplotlib(plt_objs[0], width=400)
            time_graph_pane = pn.pane.Matplotlib(plt_objs[1], width=400)
            pie_chart_pane = pn.pane.Matplotlib(plt_objs[2], width=400)
            stacked_bar_pane = pn.pane.Matplotlib(plt_objs[3], width=400)
            return pn.Column(
                pn.Row(bar_plot_pane, pie_chart_pane),
                pn.Row(time_graph_pane, stacked_bar_pane)
            )
        else:
            return pn.pane.Markdown("No data available for the selected vendor and category.")
    else:
        plt_objs = create_cloud_plots(vendor)
        if plt_objs:
            severity_pane = pn.pane.Matplotlib(plt_objs[0], width=600)
            
            pie_panes = [pn.pane.Matplotlib(fig, width=400) for fig in plt_objs[1:]]

            # Create a dynamic grid for the pie charts
            grid_size = len(pie_panes)
            if grid_size == 1:
                pie_chart_grid = pn.Row(pie_panes[0])
            elif grid_size == 2:
                pie_chart_grid = pn.Row(*pie_panes)
            elif grid_size == 3:
                pie_chart_grid = pn.Column(
                    pn.Row(*pie_panes[:2]),
                    pn.Row(pie_panes[2])
                )
            elif grid_size >= 4:
                pie_chart_grid = pn.GridBox(*pie_panes, ncols=2)

            return pn.Column(
                severity_pane,
                pie_chart_grid
            )
        else:
            return pn.pane.Markdown("No data available for the selected vendor and category.")

# Bind the widgets to the update function
bound_plots = pn.bind(update_plots, vendor_search, data_selector)

# Create a Panel layout to display widgets and plots
def create_dashboard():
    dashboard = pn.template.FastListTemplate(
        title='Vendor Data Dashboard',
        sidebar=[
            pn.pane.Markdown("## Supply chain vulnerability analysis"),
            pn.layout.Divider(),
            vendor_search,
            pn.layout.Divider(),
            data_selector,
            pn.layout.Divider(),
            pn.pane.JPG(r"../static/banner.jpg", sizing_mode='scale_width'),  # Use relative path
            pn.layout.Divider()
        ],
        main=[
            pn.pane.Markdown("### Plot Area"),
            bound_plots
        ]
    )
    return dashboard

# Serve the dashboard
if __name__ == '__main__':
    dashboard = create_dashboard()
    dashboard.show()
