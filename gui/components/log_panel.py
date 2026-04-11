import customtkinter as ctk


class LogPanel(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.level_var = ctk.StringVar(value="ALL")

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(top, text="Nhật ký hệ thống", font=ctk.CTkFont(family="Segoe UI Semibold", size=12)).grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkOptionMenu(top, variable=self.level_var, values=["ALL", "INFO", "SUCCESS", "WARNING", "ERROR"]).grid(
            row=0, column=1, rowspan=2, padx=(8, 8)
        )
        ctk.CTkButton(top, text="Clear", width=70, command=self.clear).grid(row=0, column=2, rowspan=2)

        self.text = ctk.CTkTextbox(self)
        self.text.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.text.configure(state="disabled")

    def append(self, message: str) -> None:
        level = self.level_var.get()
        if level != "ALL" and f"[{level}]" not in message:
            return
        self.text.configure(state="normal")
        self.text.insert("end", message)
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
