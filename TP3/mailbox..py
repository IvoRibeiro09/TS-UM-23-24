import tkinter as tk
from tkinter import messagebox

class EmailInboxApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Caixa de Entrada de E-mail")
        
        self.messages = [
            {"sender": "fulano@email.com", "subject": "Assunto do Email 1", "body": "Corpo do Email 1"},
            {"sender": "ciclano@email.com", "subject": "Assunto do Email 2", "body": "Corpo do Email 2"},
            {"sender": "beltrano@email.com", "subject": "Assunto do Email 3", "body": "Corpo do Email 3"}
        ]
        
        self.create_widgets()
        self.populate_listbox()
        
    def create_widgets(self):
        self.frame_left = tk.Frame(self.master)
        self.frame_left.pack(side=tk.LEFT, padx=40, pady=40)
        
        self.listbox = tk.Listbox(self.frame_left, width=20, height=15)
        self.listbox.pack()
        
        self.frame_right = tk.Frame(self.master)
        self.frame_right.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.lbl_sender = tk.Label(self.frame_right, text="Remetente:")
        self.lbl_sender.pack(anchor=tk.W)
        
        self.lbl_sender_val = tk.Label(self.frame_right, text="")
        self.lbl_sender_val.pack(anchor=tk.W)
        
        self.lbl_subject = tk.Label(self.frame_right, text="Assunto:")
        self.lbl_subject.pack(anchor=tk.W)
        
        self.lbl_subject_val = tk.Label(self.frame_right, text="")
        self.lbl_subject_val.pack(anchor=tk.W)
        
        self.lbl_body = tk.Label(self.frame_right, text="Corpo:")
        self.lbl_body.pack(anchor=tk.W)
        
        self.lbl_body_val = tk.Label(self.frame_right, text="")
        self.lbl_body_val.pack(anchor=tk.W)
        
        self.btn_delete = tk.Button(self.frame_right, text="Apagar", command=self.delete_email)
        self.btn_delete.pack(side=tk.BOTTOM, pady=10)
        
        self.listbox.bind('<<ListboxSelect>>', self.display_selected_email)
        
    def populate_listbox(self):
        for message in self.messages:
            self.listbox.insert(tk.END, f"De: {message['sender']} - Assunto: {message['subject']}")
            
    def display_selected_email(self, event):
        try:
            selected_index = self.listbox.curselection()[0]
            selected_message = self.messages[selected_index]
            self.lbl_sender_val.config(text=selected_message['sender'])
            self.lbl_subject_val.config(text=selected_message['subject'])
            self.lbl_body_val.config(text=selected_message['body'])
        except IndexError:
            pass
            
    def delete_email(self):
        try:
            selected_index = self.listbox.curselection()[0]
            self.listbox.delete(selected_index)
            del self.messages[selected_index]
            self.clear_display()
        except IndexError:
            messagebox.showwarning("Atenção", "Por favor, selecione um e-mail para apagar.")
            
    def clear_display(self):
        self.lbl_sender_val.config(text="")
        self.lbl_subject_val.config(text="")
        self.lbl_body_val.config(text="")

def main():
    root = tk.Tk()
    app = EmailInboxApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
