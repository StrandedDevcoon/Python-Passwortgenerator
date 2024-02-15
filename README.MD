## Passwortgenerator
**Beschreibung**

Der Passwortgenerator ist ein einfaches und intuitives Werkzeug mit grafischer Benutzeroberfläche, das auf Knopfdruck komplexe und sichere Passwörter generiert.  
Mit Python und der PyQt5-Bibliothek entwickelt, ermöglicht es den Benutzern, ihre Passwörter nach ihren Bedürfnissen zu gestalten.

**Funktionen**

Anpassen der Passwortlänge.  
Einbeziehung von Ziffern (0-9) in das Passwort.  
Einbeziehung von Großbuchstaben (A-Z) in das Passwort.  
Einbeziehung von Symbolen (!@#$%&*) in das Passwort.  
Option zum Befüllen der Passwortfelder mit einem generierten Passwort.  
Option zum Kopieren des Passworts in die Zwischenablage mit nur einem Klick. 

**Installation und Einrichtung**

Der Passwortgenerator erfordert Python 3.11.3 oder höher und einige andere Abhängigkeiten (PyQt5, secrets, string, etc.). Um das Repository zu klonen und diese Anwendung zu verwenden, können Sie die folgenden Schritte durchführen:  
1. Installieren Sie Python, falls es noch nicht auf Ihrem Rechner installiert ist. Sie können es von der offiziellen Python-Website https://www.python.org/ herunterladen.


2. Öffnen Sie ein Terminal-/Befehlsfenster.


3. Navigieren Sie zu dem Verzeichnis, in das Sie das Repository klonen möchten.

```
cd pfad-zum-gewünschten-verzeichnis
```
4. Klonen Sie das Repository:
```
git clone https://git.lvckyworld.dev/titas.s/python-passwortgenerator
```
5. Nachdem Sie das Repository geklont haben, navigieren Sie in das Verzeichnis:
```
cd python-passwortgenerator
```
6. Installieren Sie die notwendigen Abhängigkeiten:
```
pip install PyQt5
```

## Gebrauchsanweisung

- Sie sehen die GUI des Passwortgenerators.
- Geben Sie Ihre gewünschte Passwortlänge in das Feld "Länge des Passworts" ein.
- Aktivieren/deaktivieren Sie die Kontrollkästchen, um Ziffern, Großbuchstaben oder Symbole im Passwort ein- oder auszuschließen.
- Klicken Sie auf die Schaltfläche "Generieren", um das Passwort zu generieren. Das Passwort wird im Feld "Generiertes Passwort" angezeigt.
- Klicken Sie auf die Schaltfläche "Kopieren", um das generierte Passwort in Ihre Zwischenablage zu kopieren.

## Mitwirken

Pull-Anfragen sind willkommen!  
Bei größeren Änderungen öffnen Sie bitte zuerst ein Issue, um zu besprechen, was Sie ändern möchten.