import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QCheckBox, QLineEdit,
                             QMessageBox, QFrame)
from PyQt5.QtGui import QFont
import secrets
import string


def generate_password(length, digits, upper, symbols):
    chars = string.ascii_lowercase
    if digits:
        chars += string.digits
    if upper:
        chars += string.ascii_uppercase
    if symbols:
        chars += string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.setWindowTitle("Passwort Generator")
        self.setGeometry(100, 100, 300, 300)

        layout = QVBoxLayout()

        self.length_label = QLabel("Länge des Passworts:")
        self.length_label.setFont(QFont("Arial", 14))
        layout.addWidget(self.length_label)

        self.length_var = QLineEdit()
        layout.addWidget(self.length_var)

        self.digits_var = QCheckBox("Zahlen einbeziehen")
        layout.addWidget(self.digits_var)

        self.upper_var = QCheckBox("Großbuchstaben einbeziehen")
        layout.addWidget(self.upper_var)

        self.symbols_var = QCheckBox("Symbole einbeziehen")
        layout.addWidget(self.symbols_var)

        self.result_label = QLabel("Generiertes Passwort")
        layout.addWidget(self.result_label)

        self.result_var = QLineEdit()
        layout.addWidget(self.result_var)

        self.generate_button = QPushButton("Generieren")
        self.generate_button.clicked.connect(self.generate_password_clicked)
        layout.addWidget(self.generate_button)

        self.copy_button = QPushButton("Kopieren")
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        layout.addWidget(self.copy_button)

        frame = QFrame()
        frame.setLayout(layout)
        self.setCentralWidget(frame)

    def generate_password_clicked(self):
        try:
            password = generate_password(int(self.length_var.text()), self.digits_var.isChecked(), self.upper_var.
                                         isChecked(), self.symbols_var.isChecked())
            self.result_var.setText(password)
        except ValueError:
            QMessageBox.about(self, "Fehler", "Die Länge muss eine Ganzzahl sein")

    def copy_to_clipboard(self):
        password = self.result_var.text()
        QApplication.clipboard().setText(password)


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()