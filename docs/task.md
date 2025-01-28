## Project Description
The goal is to build an application for posting short, formatted public messages with the ability to confirm their authorship.

A user can create an account in the system and log into it. During login, two-factor authentication (2FA) must be used. Acceptable 2FA methods are: TOTP, HOTP.

The application allows (at a minimum):
- viewing a user's public page with the content of their messages,
- adding a new message containing simple formatting (e.g., bold, italic text, embedded images),
- signing a message in a way that can be verified
- changing the password (this should also require 2FA).

Sensitive data must be stored securely within the system and must not be accessible to other users.

The application's authentication module should include:
- input validation (with a negative bias),
- delays and attempt limits (to hinder remote guessing and brute-force attacks),
- limited error feedback (e.g., regarding the reason for authentication denial),
- secure password storage (using cryptographic hash functions, salting, multiple hashing),
- password strength checks to educate users on security.

Before starting work on the project, include a document describing the planned technology stack, architecture, algorithms, and key design decisions.

At the end, prepare a short presentation (5 minutes). The code must be made available to the reviewer **before** the presentation. The presentation may include a bibliography as the last slide.

## Requirements
- containerization using Docker \
`$ docker-compose up` or `$ sh run-docker.sh` (if this point is not implemented, the application is graded for a maximum of 15 points)
- the application must have a database (SQL, SQLite is acceptable),
- secure connection to the application (encrypted connection) **using a web server (NGINX or Apache HTTPd) as an intermediary (proxy)**
- all user inputs must be validated with a negative bias
- user access to resources must be verified
- the number of failed login attempts must be tracked
- password strength (e.g., entropy) must be checked
- introduce a delay during login
- when using a framework (or module), a thorough understanding of its implementation is required

## Additional Features (Desirable)
- protection against Cross-Site Request Forgery (CSRF/XSRF tokens)
- password recovery mechanism: \
The user requests a password reset, and a link would be sent: ... \
to the email address: ...
- system monitoring (e.g., to inform the user about new devices connected to their account)
- implementation of reasonable and effective honeypots
- Content-Security-Policy mechanism
- disabling the `Server` header

---

## Opis projektu
Celem jest zbudowanie aplikacji do zamieszczania krótkich, formatowanych publicznych wiadomości z możliwością potwierdzania ich autorstwa.

Użytkownik może założyć sobie konto w systemie oraz zalogować się do niego. Podczas logowania należy wykorzystać autentykację dwuetapową (2FA). Dopuszczalne metody 2FA to: TOTP, HOTP.

Aplikacja pozwala na (co najmniej):
- zobaczenie publicznej strony użytkownika z treścią jego wiadomości,
- dodanie nowej wiadomości zawierającej proste formatowanie (np. pogrubienie, pochylenie tekstu, zagnieżdżenie obrazka),
- podpisanie wiadomości w sposób, który da się zweryfikować,
- zmianę hasła (tutaj również należy wykorzystać 2FA).

Dane wrażliwe muszą być przechowywane w systemie w sposób bezpieczny i nie mogą być dostępne dla innych użytkowników.

Moduł uwierzytelniania aplikacji powinien zakładać:
- walidację danych wejściowych (z negatywnym nastawieniem),
- opóźnienia i limity prób (żeby utrudnić zdalne zgadywanie i atak brute-force),
- ograniczone informowanie o błędach (np. o przyczynie odmowy uwierzytelenia),
- bezpieczne przechowywanie hasła (wykorzystanie kryptograficznych funcji mieszających, wykorzystanie soli, wielokrotne hashowanie),
- kontrola siły hasła, żeby uświadomić użytkownikowi problem.

Przed rozpoczęciem pracy nad projektem należy załączyć dokument, w którym zostanie opisany planowany stos technologiczny, architektura, wykorzystane algorytmy i kluczowe decyzje projektowe.

Na koniec należy przygotować krótką prezentację (5 min.). Kod musi zostać udostępniony do wglądu prowadzącemu _przed_ prezentacją. Prezentacja może zawierać jako ostatni slajd bibliografię.

## Wymagania
- skonteneryzowanie przy pomocą Docker \
`$ docker-compose up` lub `$ sh run-docker.sh` (w przypadku niezrealizowania tego podpunktu aplikacja jest oceniana za maksymalnie 15pkt)
- aplikacja posiada bazę danych (SQL, może być SQLite),
- bezpieczne połączenie z aplikacją (szyfrowane połączenie) **wykorzystujące serwer WWW (NGINX lub Apache HTTPd) jako pośrednika (proxy)**
- wszystkie dane wejściowe od użytkownika podlegają walidacji z negatywnym nastawieniem
- weryfikowany jest dostęp użytkowników do zasobów
- weryfikacja liczby nieudanych prób logowania
- sprawdzanie jakości hasła (np. jego entropii)
- dodać opóźnienie podczas logowania
- wykorzystując szkielet aplikacji (czy moduł) należy dokładnie wiedzieć jak jest on zaimplementowany

## Elementy dodatkowe (pożądane)
- zabezpieczenie przeciwko Cross-Site Request Forgery (żetony CSRF/XSRF)
- możliwość odzyskania dostępu w przypadku utraty hasła: \
Użytkownik poprosił o zmianę hasła, wysłałbym mu link: ... \
na adres e-mail: ...
- monitorowanie pracy systemu (np. żeby poinformować użytkownika o nowych komputerach, które łączyły się z jego kontem)
- zostawienie rozsądnych i skutecznych honeypots
- mechanizm Content-Security-Policy
- wyłączenie nagłówka Server