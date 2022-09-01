# Automatic Dynamic Analysis on iOS devices
### Tesi di laurea magistrale
### Computer Engineering - Software Platforms and Cybersecurity
### Università di Genova
## Prerequisiti
* Sistema Operativo macOS 
  * [Homebrew](https://brew.sh)
  * Python 3.8+
  * Frida (pip install frida)
  * ios-deploy (brew install ios-deploy)
  * lxml (pip install lxml)
  * frida-tools (pip install frida-tools)
  * [Appium Desktop](https://github.com/appium/appium-desktop/releases)
  * xCode per la configurazione di WDA incluso in Appium Desktop: vedere il capitolo "[full manual configuration di questa guida](https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/)"
* dispositivo fisico con Jailbreak attivo
  * [Frida installato da Cydia](https://frida.re/docs/ios/)
## Istruzioni per l'installazione dell'App
Attenzione! A causa delle restrizioni di Apple è necessario anzitutto che le App da testare siano state precedentemente
firmate tramite xCode oppure con tool specifici, ad esempio [iOS App Signer](https://dantheman827.github.io/ios-app-signer/)
(fare fede alle istruzioni presente nel link per eventualmente procedere alla generazione di un certificato).
## Istruzioni
1. Connettere il dispositivo di test tramite USB al Mac mantenendolo sempre con lo schermo acceso (in iOS 14: *impostazini>Schermo e luminosità>Blocco automatico e selezionare 'mai'*)
2. Avviare Appium Desktop assicurandosi che i parametri corrispondano alla seguente immagine:
![configurazione di default appium](/docs/appium_default.png)
3. Modificare i parametri di configurazione richiesti in *caps.json*
## Disclaimer
il presente progetto è stato sviluppato e testato su un Mac Intel e macOS 12 (Monterey).
Non escludo la possibilità del funzionamento su Macchine Apple Silicon, tuttavia è probabile che saranno necessari alcuni
adattamenti nel codice.

Lo script strace (in particolar modo per quanto riguarda tracer.js) non è integralmente opera mia, si rimanda all'apposita
licenza di utilizzo (LICENSE)