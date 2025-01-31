# 🔐 2-Factor Authentication System  

**Author:** Maxim Casiana - 2B4  

## 📌 Overview  

This project implements a **Two-Factor Authentication (2FA) system** that ensures secure communication between a **server** and **multiple client applications**. The system enhances authentication security by requiring a secondary verification code before granting access.  

---

## 🚀 How It Works  

A project that have the functionality of a 2FA communication between server and client.
How does it work:
I start by storing the predefined list of n apps in a database. Each client app will
be associated with an application set - username from the database. When a user
wants to authenticate, the corresponding app client will send a request to receive the code
2FA (optional because it can send the message 'no' and the client will not receive a 2FA code, via
therefore he will not have access to this code and cannot authenticate using the code
2FA). The 2FA server receives concurrently (TCP/IP) all requests received from clients
and it will also generate/regenerate the 2FA code for each app every time
receives a message from ClientApp.
To validate the functionality of the 2FA application, I will develop a client and a server
additional ( clientAd /serverAd ). The additional customer will basically be the user who enters the
on the keyboard an application name, a username and will also have a choice to make
between whether to send an identity confirmation notification or whether to enter a
code from the 2FA app. It sends the information and the choice made to the additional server
which retrieves the information, checks if the user (username) is found in the database with
users registered in the application and sends it to the 2FA server for verification. It sends
the information further to the 2FA client to validate the existence of an application that has
the given username. After validation, an accept/reject is sent to the 2FA server and it to
in turn sends the accept/reject to the additional server, which finally sends
to the add-on client and will show the user whether to accept or decline authentication. Chart
is the one above.
