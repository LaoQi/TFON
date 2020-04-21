import tkinter as tk


class Rose(tk.Frame):
    def __init__(self, r, **kw):
        super().__init__(**kw)
        self.root = r
        self._phrase = None
        self.phrase_entry = tk.Entry(self.root, show="*")
        self.phrase_entry.pack()
        self.button = tk.Button(self.root, text="ok", command=self.wait_phrase)
        self.button.pack()

        self._status_bar = tk.Label(self.root, )

    def wait_phrase(self):
        self._phrase = self.phrase_entry.get()

    def valid_phrase(self):
        print(self._phrase)


if __name__ == '__main__':
    root = tk.Tk()
    root.title("TFON")
    Rose(root).wait_phrase()
    root.mainloop()
