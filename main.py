#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Nmap Scanner GUI
A modern, beautiful GUI application for network scanning using Nmap.

Author: mdnoyon9758 (https://github.com/mdnoyon9758)
Version: 1.0.0
License: MIT
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import json
import os
import sys
import ipaddress
import socket
from datetime import datetime
from scanner.nmap_wrapper import NmapScanner
from scanner.parser import NmapParser

class NmapGui(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("🔍 Advanced Nmap Scanner")
        self.geometry("1000x700")
        self.minsize(800, 600)
        
        # Set appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Initialize scanner
        self.scanner = NmapScanner()
        self.is_scanning = False
        
        self.create_widgets()
        
    def create_widgets(self):
        # Left sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        
        # Logo
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🔍 Nmap Scanner", 
                                      font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Target input
        self.target_label = ctk.CTkLabel(self.sidebar_frame, text="Target:", 
                                        font=ctk.CTkFont(size=14, weight="bold"))
        self.target_label.grid(row=1, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.target_entry = ctk.CTkEntry(self.sidebar_frame, width=240, 
                                        placeholder_text="192.168.1.1 or example.com")
        self.target_entry.grid(row=2, column=0, padx=20, pady=(0, 10))
        
        # Scan type
        self.scan_type_label = ctk.CTkLabel(self.sidebar_frame, text="Scan Type:", 
                                           font=ctk.CTkFont(size=14, weight="bold"))
        self.scan_type_label.grid(row=3, column=0, padx=20, pady=(10, 5), sticky="w")
        
        self.scan_type_var = ctk.StringVar(value="Quick Scan")
        self.scan_type_menu = ctk.CTkOptionMenu(self.sidebar_frame, width=240,
                                               values=["Quick Scan", "Intense Scan", 
                                                      "Ping Scan", "Port Scan", 
                                                      "Service Detection"],
                                               variable=self.scan_type_var)
        self.scan_type_menu.grid(row=4, column=0, padx=20, pady=(0, 10))
        
        # Port range
        self.port_label = ctk.CTkLabel(self.sidebar_frame, text="Port Range:", 
                                      font=ctk.CTkFont(size=14, weight="bold"))
        self.port_label.grid(row=5, column=0, padx=20, pady=(10, 5), sticky="w")
        
        self.port_entry = ctk.CTkEntry(self.sidebar_frame, width=240, 
                                      placeholder_text="1-1000 or 22,80,443")
        self.port_entry.grid(row=6, column=0, padx=20, pady=(0, 10))
        
        # Buttons
        self.scan_button = ctk.CTkButton(self.sidebar_frame, width=240, height=40,
                                        text="🚀 Start Scan", 
                                        font=ctk.CTkFont(size=16, weight="bold"),
                                        command=self.start_scan)
        self.scan_button.grid(row=7, column=0, padx=20, pady=10)
        
        self.stop_button = ctk.CTkButton(self.sidebar_frame, width=240, height=35,
                                        text="⏹️ Stop Scan",
                                        fg_color="#dc3545", hover_color="#c82333",
                                        command=self.stop_scan, state="disabled")
        self.stop_button.grid(row=8, column=0, padx=20, pady=(0, 10))
        
        # Save results button
        self.save_button = ctk.CTkButton(self.sidebar_frame, width=240, height=35,
                                        text="💾 Save Results",
                                        fg_color="#28a745", hover_color="#218838",
                                        command=self.save_results)
        self.save_button.grid(row=9, column=0, padx=20, pady=(0, 10))
        
        # Clear button
        self.clear_button = ctk.CTkButton(self.sidebar_frame, width=240, height=35,
                                         text="🗑️ Clear Results",
                                         fg_color="#6c757d", hover_color="#5a6268",
                                         command=self.clear_results)
        self.clear_button.grid(row=10, column=0, padx=20, pady=(0, 20))
        
        # Theme switch
        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Theme:", 
                                                 font=ctk.CTkFont(size=12))
        self.appearance_mode_label.grid(row=11, column=0, padx=20, pady=(10, 5), sticky="w")
        
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, 
                                                            values=["Dark", "Light", "System"],
                                                            command=self.change_appearance_mode)
        self.appearance_mode_optionemenu.grid(row=12, column=0, padx=20, pady=(0, 20))
        
        # Main content area
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        
        # Status bar
        self.status_frame = ctk.CTkFrame(self.main_frame, height=50)
        self.status_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(self.status_frame, text="Ready to scan", 
                                        font=ctk.CTkFont(size=14))
        self.status_label.grid(row=0, column=0, padx=20, pady=15, sticky="w")
        
        self.progress_bar = ctk.CTkProgressBar(self.status_frame, width=200)
        self.progress_bar.grid(row=0, column=1, padx=20, pady=15, sticky="e")
        self.progress_bar.set(0)
        
        # Results area
        self.results_frame = ctk.CTkFrame(self.main_frame)
        self.results_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.results_frame.grid_rowconfigure(0, weight=1)
        
        self.results_textbox = ctk.CTkTextbox(self.results_frame, 
                                             font=ctk.CTkFont(family="Consolas", size=12))
        self.results_textbox.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
    def change_appearance_mode(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode.lower())
        
    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target address")
            return
            
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_label.configure(text=f"Scanning {target}...")
        self.progress_bar.set(0.1)
        
        # Clear previous results
        self.results_textbox.delete(1.0, tk.END)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.perform_scan, args=(target,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def perform_scan(self, target):
        try:
            scan_type = self.scan_type_var.get()
            port_range = self.port_entry.get().strip()
            
            self.progress_bar.set(0.3)
            
            # Perform the scan
            results = self.scanner.scan(target, scan_type, port_range)
            
            self.progress_bar.set(0.8)
            
            # Parse and format results
            parser = NmapParser()
            formatted_results = parser.format_results(results, target, scan_type)
            
            self.progress_bar.set(1.0)
            
            # Update UI in main thread
            self.after(0, self.update_results, formatted_results)
            
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            self.after(0, self.update_results, error_msg)
        finally:
            self.after(0, self.scan_complete)
            
    def update_results(self, results):
        self.results_textbox.insert(tk.END, results)
        
    def scan_complete(self):
        self.is_scanning = False
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_label.configure(text="Scan completed")
        self.progress_bar.set(0)
        
    def stop_scan(self):
        # Note: This is a simplified stop - in a real implementation,
        # you'd need to handle process termination
        self.is_scanning = False
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_label.configure(text="Scan stopped")
        self.progress_bar.set(0)
        
    def save_results(self):
        content = self.results_textbox.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No results to save")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Results saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                
    def clear_results(self):
        self.results_textbox.delete(1.0, tk.END)
        self.status_label.configure(text="Results cleared")

if __name__ == "__main__":
    app = NmapGui()
    app.mainloop()
