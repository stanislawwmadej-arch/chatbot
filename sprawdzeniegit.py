def sprawdz_gitignore():
    try:

        with open(".gitignore", "r", encoding="utf-8") as plik:

            zawartosc = plik.read()

    except FileNotFoundError:

        print("BRAK pliku .gitignore! Stwórz go jak najszybciej.")

        return

    if ".env" in zawartosc:

        print("OK: .env jest wymienione w .gitignore.")

    else:

        print("UWAGA: .env NIE jest wymienione w .gitignore!")

sprawdz_gitignore()