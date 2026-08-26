"""
main.py – Project Doctor GUI.
"""

import sys
from pathlib import Path
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from typing import Optional, List, Dict

from scanner import ProjectScanner, ScanResult, Severity, Category, calculate_scores
from fixer import BackupManager, SafeFixer


class ProjectDoctorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Project Doctor")
        self.geometry("1100x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.selected_project: Optional[Path] = None
        self.scan_results: List[ScanResult] = []
        self.scan_stats: Dict = {}
        self.scores: Dict[str, float] = {}

        # Backup & fixer
        self.backup_manager = BackupManager(Path.home() / "ProjectDoctorBackups")
        self.safe_fixer = SafeFixer(self.backup_manager)

        self._build_ui()

    def _build_ui(self):
        # Top bar
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=10)

        self.project_label = ctk.CTkLabel(top, text="No project selected", font=("Arial", 14))
        self.project_label.pack(side="left", padx=10)

        select_btn = ctk.CTkButton(top, text="Select Project", command=self.select_project)
        select_btn.pack(side="left", padx=5)

        scan_btn = ctk.CTkButton(top, text="Scan", command=self.start_scan, fg_color="green")
        scan_btn.pack(side="left", padx=5)

        fix_btn = ctk.CTkButton(top, text="Fix Safe Issues", command=self.fix_safe_issues)
        fix_btn.pack(side="left", padx=5)

        # Main content area: two columns
        content = ctk.CTkFrame(self)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=3)

        # Left panel: health score and stats
        left = ctk.CTkFrame(content)
        left.grid(row=0, column=0, sticky="nsew", padx=(0,10))

        self.score_label = ctk.CTkLabel(left, text="--", font=("Arial", 48, "bold"))
        self.score_label.pack(pady=20)

        self.category_scores_frame = ctk.CTkFrame(left)
        self.category_scores_frame.pack(fill="x", padx=10, pady=10)

        self.stats_label = ctk.CTkLabel(left, text="", justify="left", anchor="w")
        self.stats_label.pack(padx=10, pady=10, fill="x")

        # Right panel: results list
        right = ctk.CTkFrame(content)
        right.grid(row=0, column=1, sticky="nsew")

        self.results_container = ctk.CTkScrollableFrame(right)
        self.results_container.pack(fill="both", expand=True, padx=10, pady=10)

    def select_project(self):
        folder = filedialog.askdirectory(title="Select Project Folder")
        if folder:
            self.selected_project = Path(folder)
            self.project_label.configure(text=f"Project: {self.selected_project.name}")

    def start_scan(self):
        if not self.selected_project:
            messagebox.showerror("Error", "Please select a project folder first.")
            return
        # Disable scan button? We'll just run in thread
        threading.Thread(target=self._run_scan, daemon=True).start()
        self.score_label.configure(text="Scanning...")

    def _run_scan(self):
        scanner = ProjectScanner()
        results, stats = scanner.scan(self.selected_project)
        scores = calculate_scores(results)

        self.scan_results = results
        self.scan_stats = stats
        self.scores = scores

        # Update UI on main thread
        self.after(0, self._update_results_display)

    def _update_results_display(self):
        if not self.scan_results:
            return

        # Score
        overall = self.scores.get("overall", 0)
        self.score_label.configure(text=f"{overall:.0f}/100")

        # Category scores
        for widget in self.category_scores_frame.winfo_children():
            widget.destroy()
        for cat, score in self.scores.items():
            if cat == "overall":
                continue
            row = ctk.CTkFrame(self.category_scores_frame)
            row.pack(fill="x", padx=5, pady=2)
            ctk.CTkLabel(row, text=cat.capitalize(), width=100).pack(side="left")
            bar = ctk.CTkProgressBar(row, width=150)
            bar.pack(side="left", padx=5)
            bar.set(score / 100)
            ctk.CTkLabel(row, text=f"{score:.0f}").pack(side="left")

        # Stats
        stats_text = (
            f"Files: {self.scan_stats.get('file_count', 0)}\n"
            f"Folders: {self.scan_stats.get('folder_count', 0)}\n"
            f"Total size: {self.scan_stats.get('total_size_mb', 0):.2f} MB\n"
            f"Problems: {len([r for r in self.scan_results if r.severity != Severity.PASSED])}"
        )
        self.stats_label.configure(text=stats_text)

        # Results list
        for widget in self.results_container.winfo_children():
            widget.destroy()

        # Filter out passed?
        for result in self.scan_results:
            if result.severity == Severity.PASSED:
                continue
            row = ctk.CTkFrame(self.results_container)
            row.pack(fill="x", padx=5, pady=3)

            color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange",
                Severity.WARNING: "yellow",
                Severity.INFO: "blue",
                Severity.PASSED: "green",
            }.get(result.severity, "white")

            ctk.CTkLabel(row, text=result.severity.value.upper(), text_color=color, width=80).pack(side="left")
            ctk.CTkLabel(row, text=result.title, width=200, anchor="w").pack(side="left", padx=5)
            if result.file_path:
                ctk.CTkLabel(row, text=str(result.file_path), width=300, anchor="w").pack(side="left", padx=5)
            if result.line_number:
                ctk.CTkLabel(row, text=f"Line {result.line_number}", width=80).pack(side="left")

            if result.file_path and result.file_path.exists():
                open_btn = ctk.CTkButton(row, text="Open", width=60, command=lambda r=result: self._open_file(r))
                open_btn.pack(side="right", padx=5)

    def _open_file(self, result: ScanResult):
        import os
        if result.file_path and result.file_path.exists():
            if os.name == 'nt':
                os.startfile(result.file_path)
            else:
                import subprocess
                subprocess.call(['xdg-open', str(result.file_path)])

    def fix_safe_issues(self):
        if not self.selected_project:
            messagebox.showerror("Error", "Select a project first.")
            return

        # Check for missing .gitignore and offer to create
        missing_gitignore = any(
            r.title == ".gitignore missing" for r in self.scan_results
        )
        if missing_gitignore:
            if messagebox.askyesno("Create .gitignore", "Create a .gitignore with recommended Python entries?"):
                created = self.safe_fixer.create_gitignore(self.selected_project)
                if created:
                    messagebox.showinfo("Done", "Created .gitignore.")
                else:
                    messagebox.showinfo("Info", ".gitignore already exists.")
        else:
            messagebox.showinfo("No fixes", "No safe fixes available.")


def main():
    app = ProjectDoctorApp()
    app.mainloop()


if __name__ == "__main__":
    main()