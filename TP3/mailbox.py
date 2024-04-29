import tkinter as tk
from tkinter import messagebox

class EmailInboxApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Caixa de Entrada de E-mail")
        self.mode = "inbox"  # Modo inicial: Caixa de entrada
        
        self.messages = [
            {"sender": "fulano@email.com", "subject": "Assunto do Email 1", "body": "Corpo do Email 1"},
            {"sender": "ciclano@email.com", "subject": "Assunto do Email 2", "body": "Corpo do Email 2"},
            {"sender": "beltrano@email.com", "subject": "Assunto do Email 3", "body": "Corpo do Email 3"}
        ]
        
        self.create_widgets()
        self.populate_listbox()
        
    def create_widgets(self):
        self.frame_left = tk.Frame(self.master, width=200)
        self.frame_left.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)
        
        self.listbox = tk.Listbox(self.frame_left, width=30, height=15)
        self.listbox.pack(side=tk.TOP, pady=10)
        
        self.frame_right = tk.Frame(self.master)
        self.frame_right.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.lbl_sender = tk.Label(self.frame_right, text="Remetente:")
        self.lbl_sender.grid(row=0, column=0, sticky=tk.W)
        
        self.lbl_sender_val = tk.Label(self.frame_right, text="")
        self.lbl_sender_val.grid(row=0, column=1, sticky=tk.W)
        
        self.lbl_subject = tk.Label(self.frame_right, text="Assunto:")
        self.lbl_subject.grid(row=1, column=0, sticky=tk.W)
        
        self.lbl_subject_val = tk.Label(self.frame_right, text="")
        self.lbl_subject_val.grid(row=1, column=1, sticky=tk.W)
        
        self.lbl_body = tk.Label(self.frame_right, text="Corpo:")
        self.lbl_body.grid(row=2, column=0, sticky=tk.W)
        
        self.lbl_body_val = tk.Label(self.frame_right, text="")
        self.lbl_body_val.grid(row=2, column=1, sticky=tk.W)
        
        self.btn_delete = tk.Button(self.frame_right, text="Apagar", command=self.delete_email)
        self.btn_delete.grid(row=3, column=0, sticky=tk.W, pady=10)
        
        self.btn_reply = tk.Button(self.frame_right, text="Responder", command=self.reply_email)
        self.btn_reply.grid(row=3, column=1, sticky=tk.E, pady=10)
        
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
        
    def reply_email(self):
        self.mode = "reply"  # Mudar para o modo de resposta
        self.clear_display()
        self.lbl_sender.config(text="Destinatário:")
        self.lbl_sender_val.config(text=self.messages[self.listbox.curselection()[0]]["sender"])
        self.lbl_subject.config(text="Assunto:")
        self.lbl_subject_val.config(text=f"RE: {self.messages[self.listbox.curselection()[0]]['subject']}")
        self.lbl_body.config(text="Corpo:")
        self.lbl_body_val.config(text="")
        self.btn_delete.config(state=tk.DISABLED)
        self.btn_reply.config(text="Enviar", command=self.send_reply)
        
    def send_reply(self):
        recipient = self.lbl_sender_val.cget("text")
        subject = self.lbl_subject_val.cget("text")
        body = self.lbl_body_val.cget("text")
        # Aqui você pode implementar a lógica para enviar o e-mail, como enviar os dados para um servidor SMTP, por exemplo
        messagebox.showinfo("Envio de Email", "E-mail enviado com sucesso!")
        self.mode = "inbox"  # Voltar para o modo de caixa de entrada
        self.btn_delete.config(state=tk.NORMAL)
        self.btn_reply.config(text="Responder", command=self.reply_email)
        self.clear_display()

def main():
    root = tk.Tk()
    app = EmailInboxApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
