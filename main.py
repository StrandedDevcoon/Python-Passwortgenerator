import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QCheckBox, QLineEdit,
                             QMessageBox, QFrame)
from PyQt5.QtGui import QFont
import secrets
import string


def generate_password(length, digits, upper, symbols):
    """
    Generate a random password.

    :param length: The length of the password.
    :param digits: A flag indicating whether to include digits in the password.
    :param upper: A flag indicating whether to include uppercase letters in the password.
    :param symbols: A flag indicating whether to include symbols in the password.
    :return: The generated password as a string.
    """
    chars = string.ascii_lowercase
    if digits:
        chars += string.digits
    if upper:
        chars += string.ascii_uppercase
    if symbols:
        chars += string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


class MainWindow(QMainWindow):
    """

    The `MainWindow` class represents the main window of a password generator application. It inherits from the
    `QMainWindow` class.

    Attributes:
        - `length_label`: QLabel - The label for the password length input field.
        - `length_var`: QLineEdit - The input field for the password length.
        - `digits_var`: QCheckBox - The checkbox for including digits in the generated password.
        - `upper_var`: QCheckBox - The checkbox for including uppercase letters in the generated password.
        - `symbols_var`: QCheckBox - The checkbox for including symbols in the generated password.
        - `result_label`: QLabel - The label for the generated password.
        - `result_var`: QLineEdit - The input field for the generated password.
        - `generate_button`: QPushButton - The button for generating a password.
        - `copy_button`: QPushButton - The button for copying the generated password to the clipboard.

    Methods:
        - `__init__()`: Initializes the `MainWindow` object and sets up the UI.
        - `generate_password_clicked()`: Generates a password based on the user's input and sets it as the generated
            password.
        - `copy_to_clipboard()`: Copies the generated password to the clipboard.

    Example usage:
        main_window = MainWindow()
        main_window.show()

    """
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
    """
    Main Method
    ------------
    Starts the application and creates a main window.

    Returns
    -------
    None

    Example
    -------
    To use this method, simply call it:

        main()

    """
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()