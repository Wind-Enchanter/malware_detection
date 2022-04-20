# cuckoo_report_analyzer
Sebuah analyzer untuk menentukan serbuah executable adalah malware(Windows based malware) atau bukan berdasarkan API calls sequence yang didapat dari report Cuckoo Sandbox, berdasarkan SIMILARITY dengan malware API sequence dataset.


### DATASET
Masukkan dataset kedalam folder ./dataset
Download dari [Google Drive](https://drive.google.com/open?id=1AqDiMJQfIhNzAhUCkH-rPK118NAcrBq3)


### HOW TO RUN

Program akan membaca report(dari Cuckoo sb) file executable, sehingga diperlukan report.json yang didapat setelah menganalisa malware menggunakan Cuckoo Sandbox.

Berikut perintah untuk menjalankan 

```
python main.py 'report.json' 
```
Program akan berjalan dan menciptakan sub-folder di dalam folder storage dengan nama yg sama dengan file executable(.exe)

### ERROR

Jika terdapat error seperti berikut :
```
IOError: [Errno 2] No such file or directory: u'/address to file'

```
Jalankan program sekali lagi, error tersebut dikarenakan folder telah dibuat, namun belum terbaca oleh program.
