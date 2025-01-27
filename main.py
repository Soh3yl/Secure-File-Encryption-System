import sys
from PyQt5.QtWidgets import QApplication
from gui import GUI

def main():
    app = QApplication(sys.argv)
    window = GUI.FileEncryptionWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()